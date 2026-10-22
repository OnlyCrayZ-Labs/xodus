// MSFS 2024 compatibility modifications: 2026-10-22; see PUBLICATION-PROVENANCE.md.
//! Versioned identity-only bridge. Tokens stay in the authenticated service.
use crate::simple_context::SimpleContext;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::models::{live::ExchangeUserTokenOutcome, secrets::Token, soap};

pub const MAGIC: u32 = 0x58445355;
const NO_USER: u32 = 0x89245106;
const AUTH_FAILED: u32 = 0x89245111;

fn identity(response: &xodus::models::xbox::XstsResponse) -> Option<(u64, u32, i64)> {
    if response.token.is_empty() || response.not_after <= chrono::Utc::now() {
        return None;
    }
    let json = serde_json::to_value(response).ok()?;
    let claims = json.get("DisplayClaims")?.get("xui")?.as_array()?;
    if claims.len() != 1 {
        return None;
    }
    let claim = &claims[0];
    let xid = claim.get("xid")?.as_str()?.parse::<u64>().ok()?;
    if xid == 0 || claim.get("uhs")?.as_str()?.is_empty() {
        return None;
    }
    let age = match claim.get("agg").and_then(|v| v.as_str()) {
        Some("Child") => 1,
        Some("Teen") => 2,
        Some("Adult") => 3,
        _ => 0,
    };
    Some((xid, age, response.not_after.timestamp()))
}

async fn authenticate_account(context: &SimpleContext) -> Result<((u64, u32, i64), String), u32> {
    let Token::Legacy(user) = context.tokens().get_user_sts_token().map_err(|_| NO_USER)? else {
        return Err(NO_USER);
    };
    let device = context.device_token.clone().ok_or(NO_USER)?;
    // Same authenticated RPS -> Xbox user -> XSTS exchange used by api::xbox::run,
    // with fallible parsing instead of panics. No new account or interactive UI.
    let issued = xodus::api::live::exchange_user_token(
        &context.client,
        user,
        "USERNAME".into(),
        device,
        None,
        Some("Silent".into()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".into(),
        &[(
            "user.auth.xboxlive.com".into(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .map_err(|_| AUTH_FAILED)?;
    let token: Token = match issued {
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(c),
        ) => c
            .security_tokens
            .into_iter()
            .next()
            .ok_or(AUTH_FAILED)?
            .into(),
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(t)) => {
            (*t).into()
        }
        _ => return Err(AUTH_FAILED),
    };
    let Token::Compact(rps) = token else {
        return Err(AUTH_FAILED);
    };
    let user = xodus::api::xbox::authenticate_xbox_user(&context.client, rps)
        .await
        .map_err(|_| AUTH_FAILED)?;
    let xsts =
        xodus::api::xbox::request_xsts_token(&context.client, user.token, "http://xboxlive.com")
            .await
            .map_err(|_| AUTH_FAILED)?;
    let verified = identity(&xsts).ok_or(AUTH_FAILED)?;
    let claims = serde_json::to_value(&xsts).map_err(|_| AUTH_FAILED)?;
    let label = claims["DisplayClaims"]["xui"][0]["gtg"]
        .as_str()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| "Current authenticated Xbox account".to_owned());
    Ok((verified, label))
}

fn encode(result: Result<(u64, u32, i64), u32>) -> [u8; 32] {
    let mut out = [0; 32];
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&1u32.to_le_bytes());
    match result {
        Ok((xid, age, expires)) => {
            out[12..16].copy_from_slice(&age.to_le_bytes());
            out[16..24].copy_from_slice(&xid.to_le_bytes());
            out[24..32].copy_from_slice(&expires.to_le_bytes());
        }
        Err(hr) => out[8..12].copy_from_slice(&hr.to_le_bytes()),
    }
    out
}

async fn authenticate(context: &SimpleContext) -> Result<(u64, u32, i64), u32> {
    authenticate_account(context).await.map(|account| account.0)
}

const ABORT: u32 = 0x80004004;
const UI_UNAVAILABLE: u32 = 0x80004001;
const TIMEOUT: u32 = 0x800705b4;
const BUSY: u32 = 0x800700aa;
static PICKER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn dialog_command(label: &str) -> tokio::process::Command {
    // No shell, executable override, persisted approval or token in arguments.
    let label: String = label
        .chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect();
    let label = label
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let mut command = tokio::process::Command::new("/usr/bin/kdialog");
    command.args(["--title", "Xodus — Xbox account selection",
        "--yes-label", "Use this account", "--no-label", "Cancel", "--yesno",
        &format!("Use this authenticated Xbox account for the requesting game?\n\n{label}\n\nTo use another account, cancel and sign in through Xodus.")]);
    command
}

async fn run_dialog(mut command: tokio::process::Command) -> Result<(), u32> {
    use std::process::Stdio;
    let mut child = command
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| {
            tracing::warn!("Account picker unavailable: KDialog could not be started or waited on");
            UI_UNAVAILABLE
        })?;
    let status = child.wait().await.map_err(|_| {
        tracing::warn!("Account picker unavailable: KDialog could not be started or waited on");
        UI_UNAVAILABLE
    })?;
    match status.code() {
        Some(0) => Ok(()),
        Some(1) => Err(ABORT), // Cancel, No, Escape and window close.
        _ => {
            tracing::warn!("Account picker unavailable: KDialog exited abnormally");
            Err(UI_UNAVAILABLE)
        }
    }
}

async fn select_with<A, F, D>(
    gate: &tokio::sync::Mutex<()>,
    mut authenticate: A,
    dialog: D,
) -> Result<(u64, u32, i64), u32>
where
    A: FnMut() -> F,
    F: std::future::Future<Output = Result<((u64, u32, i64), String), u32>>,
    D: FnOnce(&str) -> tokio::process::Command,
{
    let _guard = gate.try_lock().map_err(|_| BUSY)?;
    let (selected, label) = authenticate().await?;
    if selected.0 == 0 || selected.2 <= chrono::Utc::now().timestamp() {
        return Err(AUTH_FAILED);
    }
    run_dialog(dialog(&label)).await?;
    let (refreshed, _) = authenticate().await?;
    if refreshed.0 != selected.0 || refreshed.2 <= chrono::Utc::now().timestamp() {
        return Err(AUTH_FAILED);
    }
    Ok(refreshed)
}

async fn select_account(context: &SimpleContext) -> Result<(u64, u32, i64), u32> {
    if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("DISPLAY").is_none() {
        tracing::warn!("Account picker unavailable: service has no desktop display environment");
        // Authenticate first, preserving missing-account diagnostics.
        authenticate(context).await?;
        return Err(UI_UNAVAILABLE);
    }
    select_with(&PICKER, || authenticate_account(context), dialog_command).await
}

pub async fn handle(
    socket: &mut tokio::net::UnixStream,
    context: &SimpleContext,
) -> std::io::Result<()> {
    // Socket permissions plus reciprocal kernel credentials; no remote callers.
    if socket.peer_cred()?.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let version = socket.read_u32_le().await?;
    if version == super::title::VERSION {
        return super::title::handle(socket, context).await;
    }
    let operation = async {
        match version {
            1 => tokio::time::timeout(std::time::Duration::from_secs(45), authenticate(context))
                .await
                .unwrap_or(Err(TIMEOUT)),
            2 => tokio::time::timeout(std::time::Duration::from_secs(180), select_account(context))
                .await
                .unwrap_or(Err(TIMEOUT)),
            _ => Err(0x80070057),
        }
    };
    complete_request(socket, version, operation).await
}

async fn complete_request<F>(
    socket: &mut tokio::net::UnixStream,
    version: u32,
    operation: F,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = Result<(u64, u32, i64), u32>>,
{
    let mut extra = [0u8; 1];
    // EOF, cancellation or unexpected pipelining drops operation. Child's
    // kill_on_drop dismisses the dialog; no approval survives a disconnected client.
    let result = tokio::select! {
        result = operation => result,
        _ = socket.read(&mut extra) => return Ok(()),
    };
    tracing::debug!(
        version,
        hr = result.as_ref().err().copied().unwrap_or(0),
        "User request completed"
    );
    let mut response = encode(result);
    if version == 2 {
        response[4..8].copy_from_slice(&2u32.to_le_bytes());
    }
    socket.write_all(&response).await
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(claim: serde_json::Value) -> xodus::models::xbox::XstsResponse {
        serde_json::from_value(serde_json::json!({
            "NotAfter": (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
            "Token": "synthetic-test-only", "DisplayClaims": {"xui": [claim]}
        }))
        .unwrap()
    }
    fn test_command(script: &str) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    #[tokio::test]
    async fn selection_confirmation_failure_and_concurrency() {
        let gate = tokio::sync::Mutex::new(());
        let verified = || {
            std::future::ready(Ok((
                (123, 3, chrono::Utc::now().timestamp() + 300),
                "Test account".to_owned(),
            )))
        };
        assert_eq!(
            select_with(&gate, verified, |_| test_command("exit 0"))
                .await
                .unwrap()
                .0,
            123
        );
        assert_eq!(
            select_with(&gate, verified, |_| test_command("exit 1")).await,
            Err(ABORT)
        );
        assert_eq!(
            select_with(&gate, verified, |_| test_command("exit 254")).await,
            Err(UI_UNAVAILABLE)
        );
        assert_eq!(
            select_with(&gate, verified, |_| tokio::process::Command::new(
                "/nonexistent/xodus-dialog"
            ))
            .await,
            Err(UI_UNAVAILABLE)
        );
        let missing = || std::future::ready(Err(NO_USER));
        assert_eq!(
            select_with(&gate, missing, |_| panic!(
                "must not show UI without account"
            ))
            .await,
            Err(NO_USER)
        );
        let mut count = 0;
        let changed = || {
            count += 1;
            std::future::ready(Ok((
                (count, 3, chrono::Utc::now().timestamp() + 300),
                "Test account".to_owned(),
            )))
        };
        assert_eq!(
            select_with(&gate, changed, |_| test_command("exit 0")).await,
            Err(AUTH_FAILED)
        );
        let expired = || std::future::ready(Ok(((123, 3, 1), "Expired".to_owned())));
        assert_eq!(
            select_with(&gate, expired, |_| test_command("exit 0")).await,
            Err(AUTH_FAILED)
        );
        // A pending request owns the only prompt; another cannot consume its choice.
        let mut active = Box::pin(select_with(&gate, verified, |_| {
            test_command("exec sleep 30")
        }));
        tokio::select! {
            _ = &mut active => panic!("unexpected completion"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
        }
        assert_eq!(
            select_with(&gate, verified, |_| test_command("exit 0")).await,
            Err(BUSY)
        );
        // Dropping/timeout kills the dialog and releases the single-flight guard.
        drop(active);
        assert_eq!(
            select_with(&gate, verified, |_| test_command("exit 0"))
                .await
                .unwrap()
                .0,
            123
        );
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                select_with(&gate, verified, |_| test_command("exec sleep 30"))
            )
            .await
            .is_err()
        );
        assert_eq!(
            select_with(&gate, verified, |_| test_command("exit 0"))
                .await
                .unwrap()
                .0,
            123
        );
    }

    #[tokio::test]
    async fn selection_response_and_disconnect_over_ipc() {
        for result in [
            Ok((123, 3, chrono::Utc::now().timestamp() + 300)),
            Err(ABORT),
            Err(AUTH_FAILED),
            Err(BUSY),
            Err(TIMEOUT),
        ] {
            let (mut client, mut server) = tokio::net::UnixStream::pair().unwrap();
            let serve = complete_request(&mut server, 2, std::future::ready(result));
            let read = async {
                let mut bytes = [0u8; 32];
                client.read_exact(&mut bytes).await.unwrap();
                assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 2);
                assert_eq!(
                    u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
                    result.err().unwrap_or(0)
                );
                if result.is_err() {
                    assert_eq!(&bytes[12..], &[0u8; 20]);
                }
            };
            let (served, ()) = tokio::join!(serve, read);
            served.unwrap();
        }
        // Disconnect must drop in-flight work, not merely suppress its reply.
        struct Dropped(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let (client, mut server) = tokio::net::UnixStream::pair().unwrap();
        let operation = async move {
            let _guard = guard;
            std::future::pending::<Result<(u64, u32, i64), u32>>().await
        };
        drop(client);
        complete_request(&mut server, 2, operation).await.unwrap();
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    #[ignore = "requires desktop user to accept then cancel two account dialogs"]
    async fn desktop_confirmation() {
        println!("Accept the first Xodus test dialog, then cancel/close the second.");
        assert_eq!(
            run_dialog(dialog_command("Synthetic UI test — no account access")).await,
            Ok(())
        );
        assert_eq!(
            run_dialog(dialog_command("Synthetic UI test — cancel this dialog")).await,
            Err(ABORT)
        );
    }

    #[test]
    fn validates_claims_without_inventing_identity_or_age() {
        let r = response(serde_json::json!({"uhs":"test", "xid":"123", "agg":"Adult"}));
        assert_eq!(identity(&r).unwrap().0, 123);
        assert_eq!(identity(&r).unwrap().1, 3);
        for age in [None, Some("invalid"), Some("Child"), Some("Teen")] {
            let r = response(serde_json::json!({"uhs":"test", "xid":"123", "agg":age}));
            assert_eq!(
                identity(&r).unwrap().1,
                match age {
                    Some("Child") => 1,
                    Some("Teen") => 2,
                    _ => 0,
                }
            );
        }
        for xid in ["0", "-1", "18446744073709551616", "garbage"] {
            assert!(identity(&response(serde_json::json!({"uhs":"test", "xid":xid}))).is_none());
        }
        let mut r = r;
        r.not_after = chrono::Utc::now() - chrono::Duration::seconds(1);
        assert!(identity(&r).is_none());
    }
    #[test]
    fn failure_does_not_emit_identity() {
        let bytes = encode(Err(NO_USER));
        assert_eq!(&bytes[8..12], &NO_USER.to_le_bytes());
        assert_eq!(&bytes[12..], &[0; 20]);
        let bytes = encode(Ok((123, 2, 456)));
        assert_eq!(&bytes[16..24], &123u64.to_le_bytes());
        assert_eq!(&bytes[24..32], &456i64.to_le_bytes());
    }
    #[tokio::test]
    async fn missing_session_and_version_errors_over_ipc() {
        let tokens = std::sync::Arc::new(xodus::tokens::TokenManager::with_memory());
        let device = xodus::models::secrets::LegacyToken {
            key_name: None,
            token: String::new(),
            binary_secret: None,
            tpm_key: None,
            lifetime: soap::Timestamp {
                id: None,
                created: String::new(),
                expires: String::new(),
            },
        };
        let context = SimpleContext::new(device, tokens);
        for (version, expected) in [(1, NO_USER), (2, NO_USER), (99, 0x80070057)] {
            let (mut client, mut server) = tokio::net::UnixStream::pair().unwrap();
            let server = handle(&mut server, &context);
            let client = async {
                client.write_u32_le(version).await.unwrap();
                let mut bytes = [0; 32];
                client.read_exact(&mut bytes).await.unwrap();
                assert_eq!(
                    u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
                    expected
                );
                assert_eq!(&bytes[12..], &[0; 20]);
            };
            let (result, ()) = tokio::join!(server, client);
            result.unwrap();
        }
    }
    /// Uses the existing keychain session, an ephemeral socket, and optionally
    /// the Wine contract executable. Never starts the game or installs a service.
    #[tokio::test]
    #[ignore = "requires authenticated desktop keychain and Xbox network access"]
    async fn live_identity_ipc() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc;
        xodus::secrets::init_secrets().expect("keychain initialization failed");
        let tokens = Arc::new(xodus::tokens::TokenManager::with_keychain_and_memory());
        let device = match tokens.get_device_sts_token() {
            Ok(Token::Legacy(t)) => t,
            _ => panic!("existing device session unavailable"),
        };
        let directory =
            std::env::temp_dir().join(format!("xodus-user-test-{}", std::process::id()));
        std::fs::create_dir(&directory).expect("isolated directory unavailable");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("identity.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let trigger = cancellation.clone();
        let server = tokio::spawn(async move {
            loop {
                let socket = tokio::select! {
                    _ = trigger.cancelled() => break,
                    result = listener.accept() => result.unwrap().0,
                };
                let token = trigger.clone();
                let tokens = tokens.clone();
                let device = device.clone();
                tokio::spawn(async move {
                    super::super::router::route(socket, token, device, tokens).await;
                });
            }
        });
        let result = if let (Ok(wine), Ok(exe)) = (
            std::env::var("XODUS_TEST_WINE"),
            std::env::var("XODUS_TEST_USER_EXE"),
        ) {
            let output = tokio::process::Command::new(wine)
                .arg(exe)
                .arg("xgameruntime.dll")
                .arg(std::env::var("XODUS_TEST_USER_MODE").unwrap_or_else(|_| "live".into()))
                .arg(std::env::var("XODUS_TEST_USER_EXPECTED").unwrap_or_else(|_| "0".into()))
                .env("XODUS_SOCKET_PATH", &path)
                .env("WINEPREFIX", directory.join("prefix"))
                .env("WINEDEBUG", "-all")
                .env("WINEDLLOVERRIDES", "mscoree,mshtml=")
                .output()
                .await
                .unwrap();
            if let Ok(wine) = std::env::var("XODUS_TEST_WINE") {
                let server = std::path::Path::new(&wine)
                    .parent()
                    .unwrap()
                    .join("server/wineserver");
                for flag in ["-k", "-w"] {
                    let _ = tokio::process::Command::new(&server)
                        .arg(flag)
                        .env("WINEPREFIX", directory.join("prefix"))
                        .status()
                        .await;
                }
            }
            // The probe prints check counts only, never identity or tokens.
            println!("{}", String::from_utf8_lossy(&output.stdout));
            output.status.success()
        } else {
            let mut socket = tokio::net::UnixStream::connect(&path).await.unwrap();
            socket.write_u32_le(MAGIC).await.unwrap();
            socket.write_u32_le(1).await.unwrap();
            let mut bytes = [0; 32];
            socket.read_exact(&mut bytes).await.unwrap();
            let hr = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            println!("Identity IPC HRESULT: {hr:08x}");
            hr == 0 && u64::from_le_bytes(bytes[16..24].try_into().unwrap()) != 0
        };
        cancellation.cancel();
        server.await.unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir_all(&directory).unwrap();
        assert!(result, "existing-account identity IPC validation failed");
    }
}
