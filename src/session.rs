use base64::{engine::general_purpose, Engine};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, KDF_M_COST, KDF_P_COST, KDF_T_COST, KEY_LEN, SALT_LEN};
use crate::storage::{
    Account, CURRENT_VERSION, EncryptedVault, LegacyVerifierVault,
    parse_encrypted, parse_legacy_plaintext, parse_legacy_verifier,
    read_vault_file, save_encrypted_vault, vault_file_exists,
};

const LEGACY_VERIFIER_PLAINTEXT: &str = "VERIFY";
pub const MIN_MASTER_PASSWORD_LEN: usize = 8;

pub struct Session {
    pub key: Zeroizing<[u8; KEY_LEN]>,
    pub salt: [u8; SALT_LEN],
    pub accounts: Vec<Account>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}

pub enum InitialState {
    NeedsSetup(Vec<Account>),
    NeedsLogin(EncryptedVault),
    NeedsLoginLegacy(LegacyVerifierVault),
    Corrupted,
    IoError(String),
}

pub fn initial_state() -> InitialState {
    if !vault_file_exists() {
        return InitialState::NeedsSetup(Vec::new());
    }
    let data = match read_vault_file() {
        Ok(d) => d,
        Err(e) => return InitialState::IoError(e.to_string()),
    };
    if let Some(vault) = parse_encrypted(&data) {
        return InitialState::NeedsLogin(vault);
    }
    if let Some(legacy) = parse_legacy_verifier(&data) {
        return InitialState::NeedsLoginLegacy(legacy);
    }
    if let Some(plaintext) = parse_legacy_plaintext(&data) {
        return InitialState::NeedsSetup(plaintext);
    }
    InitialState::Corrupted
}

pub fn setup(password: &[u8], existing: Vec<Account>) -> std::io::Result<Session> {
    let salt = crypto::generate_salt();
    let key = crypto::derive_key(password, &salt, KDF_M_COST, KDF_T_COST, KDF_P_COST);
    let session = Session {
        key,
        salt,
        accounts: existing,
    };
    persist(&session)?;
    Ok(session)
}

pub fn login(vault: &EncryptedVault, password: &[u8]) -> Result<Session, ()> {
    let salt_vec = general_purpose::STANDARD
        .decode(&vault.salt)
        .map_err(|_| ())?;
    if salt_vec.len() != SALT_LEN {
        return Err(());
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&salt_vec);

    let nonce = general_purpose::STANDARD
        .decode(&vault.nonce)
        .map_err(|_| ())?;
    let ciphertext = general_purpose::STANDARD
        .decode(&vault.ciphertext)
        .map_err(|_| ())?;

    let key = crypto::derive_key(
        password,
        &salt,
        vault.kdf_m_cost,
        vault.kdf_t_cost,
        vault.kdf_p_cost,
    );

    let plaintext = crypto::decrypt(&ciphertext, &nonce, &*key)?;
    let accounts: Vec<Account> = serde_json::from_slice(&plaintext).map_err(|_| ())?;

    let mut session = Session {
        key,
        salt,
        accounts,
    };

    if vault.kdf_m_cost != KDF_M_COST
        || vault.kdf_t_cost != KDF_T_COST
        || vault.kdf_p_cost != KDF_P_COST
    {
        let new_salt = crypto::generate_salt();
        let new_key = crypto::derive_key(
            password,
            &new_salt,
            KDF_M_COST,
            KDF_T_COST,
            KDF_P_COST,
        );
        session.key = new_key;
        session.salt = new_salt;
        let _ = persist(&session);
    }

    Ok(session)
}

pub fn login_legacy(legacy: &LegacyVerifierVault, password: &[u8]) -> Result<Session, ()> {
    let salt = general_purpose::STANDARD
        .decode(&legacy.salt)
        .map_err(|_| ())?;
    let old_key = crypto::derive_key_legacy(password, &salt);

    let verified = crypto::decrypt_combined(&legacy.verifier, &*old_key)
        .map(|s| *s == LEGACY_VERIFIER_PLAINTEXT)
        .unwrap_or(false);
    if !verified {
        return Err(());
    }

    let mut accounts: Vec<Account> = Vec::with_capacity(legacy.accounts.len());
    for old in &legacy.accounts {
        let plain = crypto::decrypt_combined(&old.password, &*old_key).map_err(|_| ())?;
        accounts.push(Account {
            name: old.name.clone(),
            password: (*plain).clone(),
        });
    }

    let new_salt = crypto::generate_salt();
    let new_key = crypto::derive_key(password, &new_salt, KDF_M_COST, KDF_T_COST, KDF_P_COST);
    let session = Session {
        key: new_key,
        salt: new_salt,
        accounts,
    };
    persist(&session).map_err(|_| ())?;
    Ok(session)
}

#[derive(Debug)]
pub enum ChangeMasterError {
    WrongCurrent,
    Io(std::io::Error),
}

impl Session {
    pub fn add_account(&mut self, name: String, password: String) -> std::io::Result<()> {
        self.accounts.push(Account { name, password });
        if let Err(e) = persist(self) {
            self.accounts.pop();
            return Err(e);
        }
        Ok(())
    }

    pub fn edit_account(
        &mut self,
        idx: usize,
        new_name: Option<String>,
        new_password: Option<String>,
    ) -> std::io::Result<()> {
        if idx >= self.accounts.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "index out of range",
            ));
        }
        let backup = self.accounts[idx].clone();

        if let Some(n) = new_name {
            self.accounts[idx].name.zeroize();
            self.accounts[idx].name = n;
        }
        if let Some(p) = new_password {
            self.accounts[idx].password.zeroize();
            self.accounts[idx].password = p;
        }

        if let Err(e) = persist(self) {
            self.accounts[idx] = backup;
            return Err(e);
        }
        Ok(())
    }

    pub fn delete_account(&mut self, idx: usize) -> std::io::Result<()> {
        if idx >= self.accounts.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "index out of range",
            ));
        }
        let removed = self.accounts.remove(idx);
        if let Err(e) = persist(self) {
            self.accounts.insert(idx, removed);
            return Err(e);
        }
        Ok(())
    }

    pub fn change_master_password(
        &mut self,
        current: &[u8],
        new: &[u8],
    ) -> Result<(), ChangeMasterError> {
        let candidate = crypto::derive_key(
            current,
            &self.salt,
            KDF_M_COST,
            KDF_T_COST,
            KDF_P_COST,
        );
        if !crypto::ct_eq(&*candidate, &*self.key) {
            return Err(ChangeMasterError::WrongCurrent);
        }

        let new_salt = crypto::generate_salt();
        let new_key = crypto::derive_key(new, &new_salt, KDF_M_COST, KDF_T_COST, KDF_P_COST);
        let old_salt = self.salt;
        let old_key = std::mem::replace(&mut self.key, new_key);
        self.salt = new_salt;

        if let Err(e) = persist(self) {
            self.salt = old_salt;
            self.key = old_key;
            return Err(ChangeMasterError::Io(e));
        }
        Ok(())
    }
}

fn persist(session: &Session) -> std::io::Result<()> {
    let json = serde_json::to_vec(&session.accounts)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let plaintext = Zeroizing::new(json);
    let (nonce, ciphertext) = crypto::encrypt(&plaintext, &*session.key);

    let vault = EncryptedVault {
        version: CURRENT_VERSION,
        kdf_algo: "argon2id".to_string(),
        kdf_m_cost: KDF_M_COST,
        kdf_t_cost: KDF_T_COST,
        kdf_p_cost: KDF_P_COST,
        salt: general_purpose::STANDARD.encode(session.salt),
        nonce: general_purpose::STANDARD.encode(nonce),
        ciphertext: general_purpose::STANDARD.encode(ciphertext),
    };

    save_encrypted_vault(&vault)
}
