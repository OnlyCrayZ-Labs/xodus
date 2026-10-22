// MSFS 2024 compatibility modifications: 2026-10-22; see PUBLICATION-PROVENANCE.md.
//! Linux architecture probe stub. The licensed memfd remains the only payload.
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use tempfile::NamedTempFile;
use tokio::process::Command;
use tokio::signal::unix::{SignalKind, signal};

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or unsupported PE headers",
    )
}

fn headers(payload: &File) -> io::Result<Vec<u8>> {
    let length = payload.metadata()?.len();
    let mut dos = [0; 64];
    payload.read_exact_at(&mut dos, 0)?;
    if &dos[..2] != b"MZ" {
        return Err(invalid());
    }
    let offset = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as usize;
    // Bound all allocations and reject overlapping/truncated headers.
    if !(64..=1024 * 1024 - 264).contains(&offset) {
        return Err(invalid());
    }
    let mut pe = [0; 264];
    payload.read_exact_at(&mut pe, offset as u64)?;
    let machine = u16::from_le_bytes(pe[4..6].try_into().unwrap());
    let sections = u16::from_le_bytes(pe[6..8].try_into().unwrap()) as usize;
    let optional = u16::from_le_bytes(pe[20..22].try_into().unwrap()) as usize;
    let magic = u16::from_le_bytes(pe[24..26].try_into().unwrap());
    if &pe[..4] != b"PE\0\0"
        || sections == 0
        || sections > 96
        || !matches!(
            (machine, magic, optional),
            (0x8664, 0x20b, 240) | (0x14c, 0x10b, 224)
        )
        || u16::from_le_bytes(pe[22..24].try_into().unwrap()) & 2 == 0
    {
        return Err(invalid());
    }
    let size = u32::from_le_bytes(pe[84..88].try_into().unwrap()) as usize;
    let table_end = offset + 24 + optional + sections * 40;
    if size < table_end || size > 1024 * 1024 || size as u64 > length {
        return Err(invalid());
    }
    let mut data = vec![0; size];
    payload.read_exact_at(&mut data, 0)?;
    // Headers must not include section payload bytes.
    for section in data[offset + 24 + optional..table_end].chunks_exact(40) {
        let raw_size = u32::from_le_bytes(section[16..20].try_into().unwrap()) as u64;
        let raw_offset = u32::from_le_bytes(section[20..24].try_into().unwrap()) as u64;
        if raw_size != 0 && (raw_offset < size as u64 || raw_offset + raw_size > length) {
            return Err(invalid());
        }
    }
    Ok(data)
}

fn select<'a>(
    files: &'a [(&String, File)],
    exe: Option<&str>,
) -> io::Result<&'a (&'a String, File)> {
    let selected = match exe {
        Some(exe) => files.iter().find(|(name, _)| name.as_str() == exe),
        None => files
            .iter()
            .filter(|(name, _)| name.to_ascii_lowercase().ends_with(".exe"))
            .min_by_key(|(name, _)| *name),
    };
    selected.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not find selected encrypted executable",
        )
    })
}

fn nt_path(path: &Path) -> io::Result<String> {
    let path = path.to_str().ok_or_else(invalid)?;
    if !path.starts_with('/') || path.contains(['|', ':', '\\']) {
        return Err(invalid());
    }
    Ok(format!("\\??\\Z:{}", path.replace('/', "\\")))
}

fn game_path(root: &Path, name: &str) -> io::Result<PathBuf> {
    let relative = name.trim_start_matches('\\').replace('\\', "/");
    let path = Path::new(&relative);
    if path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(invalid());
    }
    let path = root.join(path).canonicalize()?;
    if !path.starts_with(root) {
        return Err(invalid());
    }
    Ok(path)
}

fn stub(path: &Path, payload: &File) -> io::Result<NamedTempFile> {
    let data = headers(payload)?;
    // tempfile uses exclusive creation and mode 0600; Drop unlinks on every return path.
    let mut stub = tempfile::Builder::new()
        .prefix(".xodus-launch-")
        .suffix(".exe")
        .tempfile_in(path.parent().ok_or_else(invalid)?)?;
    stub.write_all(&data)?;
    stub.as_file().set_len(payload.metadata()?.len())?;
    Ok(stub)
}

fn socket_path(
    explicit: Option<std::ffi::OsString>,
    runtime: Option<std::ffi::OsString>,
) -> Option<std::ffi::OsString> {
    explicit.or_else(|| runtime.map(|dir| PathBuf::from(dir).join("xodus.sock").into_os_string()))
}

pub(super) async fn launch(
    wine: &str,
    root: &Path,
    exe: Option<&str>,
    files: &[(&String, File)],
) -> io::Result<ExitStatus> {
    // Register before creating the stub so interrupts cannot leave an unguarded file.
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let (name, payload) = select(files, exe)?;
    let entry = game_path(root, name)?;
    let stub = stub(&entry, payload)?;
    let mut mappings = Vec::new();
    for (name, fd) in files {
        mappings.push(format!(
            "{}:{}",
            fd.as_raw_fd(),
            nt_path(&game_path(root, name)?)?
        ));
    }
    mappings.push(format!("{}:{}", payload.as_raw_fd(), nt_path(stub.path())?));
    let socket = socket_path(
        std::env::var_os("XODUS_SOCKET_PATH"),
        std::env::var_os("XDG_RUNTIME_DIR"),
    );
    let mut command = Command::new(wine);
    if let Some(socket) = socket {
        command.env("XODUS_SOCKET_PATH", socket);
    }
    let mut child = command
        .arg(stub.path())
        .env("WINE_DLL_FILE_MAP", mappings.join("|"))
        .kill_on_drop(true)
        .spawn()?;
    tokio::select! {
        status = child.wait() => status,
        _ = interrupt.recv() => { child.kill().await?; child.wait().await },
        _ = terminate.recv() => { child.kill().await?; child.wait().await },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> File {
        let mut bytes = vec![0; 1024];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[70..72].copy_from_slice(&1u16.to_le_bytes());
        bytes[84..86].copy_from_slice(&240u16.to_le_bytes());
        bytes[86..88].copy_from_slice(&2u16.to_le_bytes());
        bytes[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[148..152].copy_from_slice(&512u32.to_le_bytes());
        bytes[344..348].copy_from_slice(&512u32.to_le_bytes());
        bytes[348..352].copy_from_slice(&512u32.to_le_bytes());
        bytes[512..].fill(0xab);
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        file
    }
    #[test]
    fn resolves_socket_before_wine_filters_xdg() {
        assert_eq!(
            socket_path(
                Some("/tmp/explicit.sock".into()),
                Some("/run/user/1000".into())
            ),
            Some("/tmp/explicit.sock".into())
        );
        assert_eq!(
            socket_path(None, Some("/run/user/1000".into())),
            Some("/run/user/1000/xodus.sock".into())
        );
        assert_eq!(socket_path(None, None), None);
    }
    #[test]
    fn selection() {
        let game = "FlightSimulator2024.exe".to_string();
        let installer = "InstallUtils\\CustomInstaller.exe".to_string();
        let dll = "a.dll".to_string();
        let files = vec![
            (&installer, fixture()),
            (&dll, fixture()),
            (&game, fixture()),
        ];
        assert_eq!(select(&files, Some(&game)).unwrap().0, &game);
        assert_eq!(select(&files, None).unwrap().0, &game);
        assert!(select(&files, Some("missing.exe")).is_err());
    }
    #[test]
    fn validated_header_only_stub_and_cleanup() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("game.exe");
        std::fs::write(&original, b"ciphertext").unwrap();
        let payload = fixture();
        assert_eq!(headers(&payload).unwrap().len(), 512);
        let path;
        {
            let stub = stub(&original, &payload).unwrap();
            path = stub.path().to_owned();
            assert_eq!(
                stub.as_file().metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(bytes.len(), 1024);
            assert!(bytes[512..].iter().all(|b| *b == 0));
        }
        assert!(!path.exists());
        assert_eq!(std::fs::read(original).unwrap(), b"ciphertext");
    }
    #[test]
    fn invalid_headers() {
        for (offset, value) in [(0, 0), (68, 0), (88, 0), (149, 0), (349, 0)] {
            let file = fixture();
            file.write_all_at(&[value], offset).unwrap();
            assert!(headers(&file).is_err());
        }
        let file = fixture();
        file.set_len(100).unwrap();
        assert!(headers(&file).is_err());
    }
    #[test]
    fn nt_mapping() {
        let path = Path::new("/games/MSFS 2024/stub.exe");
        assert_eq!(
            nt_path(path).unwrap(),
            "\\??\\Z:\\games\\MSFS 2024\\stub.exe"
        );
        assert!(nt_path(Path::new("/games/a|b")).is_err());
    }
    #[tokio::test]
    async fn spawn_error_cleans_stub() {
        let dir = tempfile::tempdir().unwrap();
        let name = "game.exe".to_string();
        std::fs::write(dir.path().join(&name), b"ciphertext").unwrap();
        let files = vec![(&name, fixture())];
        assert!(
            launch("/nonexistent/xodus-wine", dir.path(), Some(&name), &files)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
    #[tokio::test]
    async fn launches_unix_stub_with_memfd_mapping() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let name = "game.exe".to_string();
        std::fs::write(dir.path().join(&name), b"ciphertext").unwrap();
        let wine = dir.path().join("wine");
        // A synthetic launcher checks the actual argv and map without printing either.
        std::fs::write(
            &wine,
            br#"#!/bin/sh
 test "${1%/*}" = "${0%/*}" || exit 11
 case "$1" in /*/.xodus-launch-*.exe) ;; *) exit 12 ;; esac
 test -f "$1" || exit 13
 nt=$(printf '%s' "$1" | tr '/' '\\')
 case "$WINE_DLL_FILE_MAP" in *":\??\Z:$nt") ;; *) exit 14 ;; esac
 fd=${WINE_DLL_FILE_MAP%%:*}
 test -f "/proc/self/fd/$fd" || exit 15
 if test -n "$XDG_RUNTIME_DIR"; then test -n "$XODUS_SOCKET_PATH" || exit 16; fi
 "#,
        )
        .unwrap();
        std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = fixture();
        let mut flags = rustix::io::fcntl_getfd(&file).unwrap();
        flags.remove(rustix::io::FdFlags::CLOEXEC);
        rustix::io::fcntl_setfd(&file, flags).unwrap();
        let files = vec![(&name, file)];
        assert!(
            launch(wine.to_str().unwrap(), dir.path(), Some(&name), &files)
                .await
                .unwrap()
                .success()
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    // Run signal handling in a separate test process to avoid changing the parent harness.
    #[tokio::test]
    async fn interrupt_helper() {
        let Some(dir) = std::env::var_os("XODUS_TEST_INTERRUPT_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let name = "game.exe".to_string();
        let files = vec![(&name, fixture())];
        let status = launch(
            dir.join("wine").to_str().unwrap(),
            &dir,
            Some(&name),
            &files,
        )
        .await
        .unwrap();
        assert!(!status.success());
    }

    #[test]
    fn interrupt_cleans_stub() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("game.exe"), b"ciphertext").unwrap();
        let wine = dir.path().join("wine");
        std::fs::write(&wine, b"#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
        std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o700)).unwrap();
        for signal in [
            nix::sys::signal::Signal::SIGINT,
            nix::sys::signal::Signal::SIGTERM,
        ] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "commands::run::linux_launch::tests::interrupt_helper",
                    "--nocapture",
                ])
                .env("XODUS_TEST_INTERRUPT_DIR", dir.path())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if std::fs::read_dir(dir.path()).unwrap().any(|e| {
                    e.unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".xodus-launch-")
                }) {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("launch stub was not created");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(child.id() as i32), signal).unwrap();
            assert!(child.wait().unwrap().success());
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        }
    }
}
