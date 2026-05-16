use std::io::{self, IsTerminal, Write};
use std::process;

use zeroize::Zeroizing;

use crate::crypto;
use crate::session::{
    self, ChangeMasterError, InitialState, Session, MIN_MASTER_PASSWORD_LEN,
};
use crate::storage;

const MAX_LOGIN_ATTEMPTS: u32 = 3;

pub fn start() {
    storage::cleanup_stale_tmp();
    let mut session = login_or_setup();
    run_menu(&mut session);
    drop(session);
    println!("Goodbye.");
}

fn login_or_setup() -> Session {
    match session::initial_state() {
        InitialState::NeedsSetup(existing) => {
            if !existing.is_empty() {
                println!("Existing accounts found in unencrypted format.");
                println!("Set up a master password to secure them.\n");
            }
            setup_flow(existing)
        }
        InitialState::NeedsLogin(vault) => login_flow(vault),
        InitialState::NeedsLoginLegacy(legacy) => {
            println!("Detected older encrypted format. Upgrading after login...\n");
            login_legacy_flow(legacy)
        }
        InitialState::Corrupted => {
            eprintln!("Vault file is unreadable or corrupted. Aborting.");
            process::exit(1);
        }
        InitialState::IoError(e) => {
            eprintln!("Failed to read vault file: {}", e);
            process::exit(1);
        }
    }
}

fn setup_flow(existing: Vec<crate::storage::Account>) -> Session {
    println!("==== Set up Master Password ====");
    loop {
        let pw1 = read_password("Enter new master password: ");
        if pw1.len() < MIN_MASTER_PASSWORD_LEN {
            println!(
                "Password must be at least {} characters.\n",
                MIN_MASTER_PASSWORD_LEN
            );
            continue;
        }
        let pw2 = read_password("Confirm master password: ");
        if !crypto::ct_eq(pw1.as_bytes(), pw2.as_bytes()) {
            println!("Passwords do not match. Try again.\n");
            continue;
        }

        match session::setup(pw1.as_bytes(), existing) {
            Ok(s) => {
                println!("\nMaster password set successfully.\n");
                return s;
            }
            Err(e) => {
                eprintln!("Failed to write vault: {}", e);
                process::exit(1);
            }
        }
    }
}

fn login_flow(vault: crate::storage::EncryptedVault) -> Session {
    println!("==== Login ====");
    for attempt in 1..=MAX_LOGIN_ATTEMPTS {
        let pw = read_password("Enter master password: ");
        match session::login(&vault, pw.as_bytes()) {
            Ok(s) => {
                println!("\nLogin successful.\n");
                return s;
            }
            Err(_) => {
                let remaining = MAX_LOGIN_ATTEMPTS - attempt;
                if remaining > 0 {
                    println!("Wrong password. {} attempt(s) remaining.\n", remaining);
                }
            }
        }
    }
    eprintln!("Too many failed attempts. Aborting.");
    process::exit(1);
}

fn login_legacy_flow(legacy: crate::storage::LegacyVerifierVault) -> Session {
    println!("==== Login (legacy format) ====");
    for attempt in 1..=MAX_LOGIN_ATTEMPTS {
        let pw = read_password("Enter master password: ");
        match session::login_legacy(&legacy, pw.as_bytes()) {
            Ok(s) => {
                println!("\nLogin successful. Vault upgraded to current format.\n");
                return s;
            }
            Err(_) => {
                let remaining = MAX_LOGIN_ATTEMPTS - attempt;
                if remaining > 0 {
                    println!("Wrong password. {} attempt(s) remaining.\n", remaining);
                }
            }
        }
    }
    eprintln!("Too many failed attempts. Aborting.");
    process::exit(1);
}

fn run_menu(session: &mut Session) {
    loop {
        println!("==== Password Manager ====");
        println!("1. Add account");
        println!("2. Show accounts");
        println!("3. Edit account");
        println!("4. Delete account");
        println!("5. Change master password");
        println!("6. Exit");

        let choice = read_input("Choose an option: ");
        match choice.as_str() {
            "1" => add_account(session),
            "2" => show_accounts(session),
            "3" => edit_account(session),
            "4" => delete_account(session),
            "5" => change_master_password(session),
            "6" => break,
            _ => println!("Invalid option, try again."),
        }
    }
}

fn add_account(session: &mut Session) {
    let name = read_input("Enter account name: ");
    if name.is_empty() {
        println!("\nName cannot be empty.\n");
        return;
    }
    let username = read_input("Enter username (leave empty for none): ");
    let password = read_password("Enter password: ");
    match session.add_account(name, username, password.to_string(), String::new(), String::new()) {
        Ok(_) => println!("\nAccount added successfully.\n"),
        Err(e) => eprintln!("Failed to save: {}", e),
    }
}

fn show_accounts(session: &Session) {
    if session.accounts.is_empty() {
        println!("\nNo accounts stored.\n");
        return;
    }
    println!("\n==== Stored Accounts ====");
    for account in &session.accounts {
        println!("------------------------");
        println!("Account:  {}", account.name);
        if !account.username.is_empty() {
            println!("Username: {}", account.username);
        }
        println!("Password: {}", account.password);
    }
    println!("------------------------\n");
}

fn edit_account(session: &mut Session) {
    let idx = match select_account(session, "Select account to edit: ") {
        Some(i) => i,
        None => return,
    };
    println!("Current name:     {}", session.accounts[idx].name);
    println!("Current username: {}", session.accounts[idx].username);
    let new_name = read_input("New name (leave empty to keep current): ");
    let new_username = read_input("New username (leave empty to keep current): ");
    let new_password = read_password("New password (leave empty to keep current): ");

    if new_name.is_empty() && new_username.is_empty() && new_password.is_empty() {
        println!("\nNothing changed.\n");
        return;
    }

    let name_opt = if new_name.is_empty() { None } else { Some(new_name) };
    let user_opt = if new_username.is_empty() {
        None
    } else {
        Some(new_username)
    };
    let pw_opt = if new_password.is_empty() {
        None
    } else {
        Some(new_password.to_string())
    };

    match session.edit_account(idx, name_opt, user_opt, pw_opt, None, None) {
        Ok(_) => println!("\nAccount updated.\n"),
        Err(e) => eprintln!("Failed to save: {}", e),
    }
}

fn delete_account(session: &mut Session) {
    let idx = match select_account(session, "Select account to delete: ") {
        Some(i) => i,
        None => return,
    };
    let name = session.accounts[idx].name.clone();
    let confirm = read_input(&format!("Type 'yes' to confirm deletion of '{}': ", name));
    if confirm != "yes" {
        println!("\nCancelled.\n");
        return;
    }
    match session.delete_account(idx) {
        Ok(_) => println!("\nAccount deleted.\n"),
        Err(e) => eprintln!("Failed to save: {}", e),
    }
}

fn change_master_password(session: &mut Session) {
    let current = read_password("Enter current master password: ");
    let new_pw = read_password("Enter new master password: ");
    if new_pw.len() < MIN_MASTER_PASSWORD_LEN {
        println!(
            "\nPassword must be at least {} characters.\n",
            MIN_MASTER_PASSWORD_LEN
        );
        return;
    }
    let confirm = read_password("Confirm new master password: ");
    if !crypto::ct_eq(new_pw.as_bytes(), confirm.as_bytes()) {
        println!("\nPasswords do not match.\n");
        return;
    }

    match session.change_master_password(current.as_bytes(), new_pw.as_bytes()) {
        Ok(_) => println!("\nMaster password changed successfully.\n"),
        Err(ChangeMasterError::WrongCurrent) => {
            println!("\nWrong current master password.\n");
        }
        Err(ChangeMasterError::Io(e)) => {
            eprintln!("Failed to save: {}", e);
        }
    }
}

fn select_account(session: &Session, prompt: &str) -> Option<usize> {
    if session.accounts.is_empty() {
        println!("\nNo accounts stored.\n");
        return None;
    }
    println!("\n==== Accounts ====");
    for (i, account) in session.accounts.iter().enumerate() {
        println!("{}. {}", i + 1, account.name);
    }
    println!("0. Cancel");

    let input = read_input(prompt);
    let n: usize = match input.parse() {
        Ok(n) => n,
        Err(_) => {
            println!("\nInvalid number.\n");
            return None;
        }
    };
    if n == 0 {
        println!("\nCancelled.\n");
        return None;
    }
    if n > session.accounts.len() {
        println!("\nOut of range.\n");
        return None;
    }
    Some(n - 1)
}

fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    input.trim().to_string()
}

fn read_password(prompt: &str) -> Zeroizing<String> {
    let raw = if io::stdin().is_terminal() {
        match rpassword::prompt_password(prompt) {
            Ok(pw) => pw,
            Err(e) => {
                eprintln!("Failed to read password: {}", e);
                process::exit(1);
            }
        }
    } else {
        print!("{}", prompt);
        io::stdout().flush().ok();
        let mut s = String::new();
        if io::stdin().read_line(&mut s).is_err() {
            eprintln!("Failed to read password.");
            process::exit(1);
        }
        s.trim_end_matches('\n').trim_end_matches('\r').to_string()
    };
    Zeroizing::new(raw)
}
