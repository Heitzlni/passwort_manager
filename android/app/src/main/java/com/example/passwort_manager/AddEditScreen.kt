@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.example.passwort_manager

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Casino
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp

/**
 * Shared add / edit form. When [initial] is null we're creating a
 * new account; otherwise we're editing it. [onSave] hands back the
 * filled-in [Account] for the caller to push into [VaultState]
 * (which stamps `updated_at`).
 */
@Composable
fun AddEditScreen(
    initial: Account?,
    onSave: (Account) -> Unit,
    onCancel: () -> Unit,
    onDelete: (() -> Unit)? = null, // shown only in edit mode
) {
    val editMode = initial != null

    var name by remember { mutableStateOf(initial?.name.orEmpty()) }
    var url by remember { mutableStateOf(initial?.url.orEmpty()) }
    var username by remember { mutableStateOf(initial?.username.orEmpty()) }
    var password by remember { mutableStateOf(initial?.password.orEmpty()) }
    var totpSecret by remember { mutableStateOf(initial?.totpSecret.orEmpty()) }
    var notes by remember { mutableStateOf(initial?.notes.orEmpty()) }

    var revealPassword by remember { mutableStateOf(false) }
    var showGenerator by remember { mutableStateOf(false) }
    var showDeleteConfirm by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    androidx.activity.compose.BackHandler { onCancel() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (editMode) "Edit entry" else "New entry") },
                navigationIcon = {
                    IconButton(onClick = onCancel) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (editMode && onDelete != null) {
                        TextButton(onClick = { showDeleteConfirm = true }) {
                            Text("Delete", color = MaterialTheme.colorScheme.error)
                        }
                    }
                    Button(
                        onClick = {
                            if (name.isBlank()) {
                                error = "Name can't be empty."
                                return@Button
                            }
                            onSave(
                                Account(
                                    name = name.trim(),
                                    url = url.trim(),
                                    username = username.trim(),
                                    password = password,
                                    totpSecret = totpSecret.trim(),
                                    notes = notes,
                                    updatedAt = initial?.updatedAt ?: 0L,
                                ),
                            )
                        },
                    ) { Text("Save") }
                    Spacer(Modifier.width(8.dp))
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            FormField("Name", name, { name = it }, required = true)
            FormField("URL", url, { url = it })
            FormField("Username", username, { username = it })

            // Password field gets the reveal toggle + a "dice" icon
            // that opens the generator dialog.
            Column {
                Text(
                    "Password",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(4.dp))
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    singleLine = true,
                    visualTransformation = if (revealPassword)
                        VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        Row {
                            IconButton(onClick = { revealPassword = !revealPassword }) {
                                Icon(
                                    if (revealPassword) Icons.Default.VisibilityOff
                                    else Icons.Default.Visibility,
                                    contentDescription = if (revealPassword) "Hide" else "Show",
                                )
                            }
                            IconButton(onClick = { showGenerator = true }) {
                                Icon(
                                    Icons.Default.Casino,
                                    contentDescription = "Generate",
                                )
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            FormField("2FA secret (Base32, optional)", totpSecret, { totpSecret = it })

            FormField(
                label = "Notes",
                value = notes,
                onValueChange = { notes = it },
                singleLine = false,
            )

            if (error != null) {
                Text(error!!, color = MaterialTheme.colorScheme.error)
            }
            Spacer(Modifier.height(40.dp))
        }
    }

    if (showGenerator) {
        GeneratePasswordDialog(
            onAccept = {
                password = it
                revealPassword = true
                showGenerator = false
            },
            onCancel = { showGenerator = false },
        )
    }

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            title = { Text("Delete entry?") },
            text = {
                Text("Remove \"${initial?.name ?: ""}\" from the vault. A tombstone is recorded so the next sync also deletes it on your laptop.")
            },
            confirmButton = {
                TextButton(onClick = {
                    showDeleteConfirm = false
                    onDelete?.invoke()
                }) {
                    Text("Delete", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirm = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun FormField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    required: Boolean = false,
    singleLine: Boolean = true,
) {
    Column {
        Text(
            label + if (required) " *" else "",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(4.dp))
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            singleLine = singleLine,
            modifier = Modifier
                .fillMaxWidth()
                .then(if (singleLine) Modifier else Modifier.heightIn(min = 96.dp)),
        )
    }
}

@Composable
private fun GeneratePasswordDialog(onAccept: (String) -> Unit, onCancel: () -> Unit) {
    var length by remember { mutableIntStateOf(PasswordGenerator.DEFAULT_LENGTH) }
    var lower by remember { mutableStateOf(true) }
    var upper by remember { mutableStateOf(true) }
    var digits by remember { mutableStateOf(true) }
    var symbols by remember { mutableStateOf(true) }
    val charset by remember(lower, upper, digits, symbols) {
        derivedStateOf {
            PasswordGenerator.Charset(
                lower = lower, upper = upper, digits = digits, symbols = symbols,
            )
        }
    }
    var generated by remember { mutableStateOf("") }

    // Auto-roll on first open and every change to the toggles.
    LaunchedEffect(length, lower, upper, digits, symbols) {
        generated = PasswordGenerator.generate(length, charset)
    }

    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Generate password") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Length: $length  (~${"%.0f".format(PasswordGenerator.entropyBits(length, charset))} bits)",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Slider(
                    value = length.toFloat(),
                    onValueChange = { length = it.toInt() },
                    valueRange = 8f..64f,
                    steps = 64 - 8 - 1,
                )

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = lower, onCheckedChange = { lower = it })
                    Text("a–z")
                    Spacer(Modifier.width(16.dp))
                    Checkbox(checked = upper, onCheckedChange = { upper = it })
                    Text("A–Z")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = digits, onCheckedChange = { digits = it })
                    Text("0–9")
                    Spacer(Modifier.width(16.dp))
                    Checkbox(checked = symbols, onCheckedChange = { symbols = it })
                    Text("!@#…")
                }

                Spacer(Modifier.height(6.dp))
                Surface(
                    tonalElevation = 2.dp,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        generated,
                        modifier = Modifier.padding(12.dp),
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    )
                }
            }
        },
        confirmButton = {
            Row {
                TextButton(onClick = {
                    generated = PasswordGenerator.generate(length, charset)
                }) { Text("Re-roll") }
                Spacer(Modifier.width(8.dp))
                Button(onClick = { onAccept(generated) }) { Text("Use") }
            }
        },
        dismissButton = {
            TextButton(onClick = onCancel) { Text("Cancel") }
        },
    )
}
