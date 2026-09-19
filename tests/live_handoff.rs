#![cfg(unix)]

pub mod support;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use support::{
    cleanup_test_base, client_shell_handshake, register_runtime_dir, register_spawned_herdr_pid,
    send_client_shell_shift_enter, unregister_spawned_herdr_pid, wait_for_client_shell_bootstrap,
    wait_for_message_variant, wait_for_socket, SERVER_MESSAGE_ENDPOINT_CONTROL,
    SERVER_MESSAGE_SERVER_SHUTDOWN,
};

struct SpawnedHerdr {
    _master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
    identity: Option<support::TestProcessIdentity>,
    config_home: PathBuf,
}

struct RequestError {
    retryable: bool,
    message: String,
}

impl Drop for SpawnedHerdr {
    fn drop(&mut self) {
        let Some(identity) = &self.identity else {
            // Armed immediately after spawn, before inspection or registration.
            // A failed inspection never authorizes a signal; an unreaped live
            // direct Child still owns its PID during this startup-only fallback.
            let cleanup = (|| -> std::io::Result<()> {
                for (signal, grace) in [
                    (libc::SIGTERM, Duration::from_millis(400)),
                    (libc::SIGKILL, Duration::from_secs(2)),
                ] {
                    if self.child.try_wait()?.is_some() {
                        return Ok(());
                    }
                    let pid = self
                        .child
                        .process_id()
                        .filter(|pid| *pid > 0 && *pid <= i32::MAX as u32)
                        .ok_or_else(|| {
                            std::io::Error::other("missing positive startup child PID")
                        })?;
                    if unsafe { libc::kill(pid as i32, signal) } != 0 {
                        let error = std::io::Error::last_os_error();
                        if error.raw_os_error() != Some(libc::ESRCH) {
                            return Err(error);
                        }
                    }
                    let end = Instant::now() + grace;
                    while Instant::now() < end {
                        if self.child.try_wait()?.is_some() {
                            return Ok(());
                        }
                        thread::sleep(Duration::from_millis(20));
                    }
                }
                Err(std::io::Error::other(
                    "startup child survived bounded TERM/KILL/reap",
                ))
            })();
            if let Err(error) = cleanup {
                if error.raw_os_error() == Some(libc::ECHILD) {
                    support::set_handoff_starting(&self.config_home, false);
                    return;
                }
                let failure = format!(
                    "startup child {:?} cleanup unresolved: {error}",
                    self.child.process_id()
                );
                support::retain_handoff_startup_failure(&self.config_home, &failure);
                if thread::panicking() {
                    eprintln!("{failure}");
                } else {
                    panic!("{failure}");
                }
            } else {
                support::set_handoff_starting(&self.config_home, false);
            }
            return;
        };
        let result =
            support::terminate_test_process(identity, Instant::now() + Duration::from_millis(2400));
        let _ = self.child.try_wait();
        match result {
            Ok(()) => unregister_spawned_herdr_pid(Some(identity.pid)),
            Err(error) if thread::panicking() => {
                eprintln!("direct child cleanup unresolved: {error}")
            }
            Err(error) => panic!("direct child cleanup unresolved: {error}"),
        }
    }
}

fn test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn fixture_root(temporary_root: &Path, explicit_root: Option<&Path>) -> std::io::Result<PathBuf> {
    // Ordinary macOS TMPDIR is too long for named-session handoff sockets.
    // A supervisor override is explicit: reject invalid/long roots, never escape
    // that supervisor's exclusively owned directory by silently falling back.
    let _ = temporary_root;
    let root = explicit_root.unwrap_or(Path::new("/tmp"));
    if !root.is_absolute()
        || root.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(std::io::Error::other(
            "fixture root must be absolute without traversal",
        ));
    }
    let canonical = fs::canonicalize(root)?;
    let tail = "h2147483647-9999/config/herdr-dev/sessions/work/herdr-handoff-2147483647.sock";
    // macOS sun_path is 104 bytes including the terminator. The short fixture
    // counter is separately bounded below, so budget its actual maximum here.
    if canonical.join(tail).as_os_str().as_encoded_bytes().len() >= 104 {
        return Err(std::io::Error::other(
            "fixture root exceeds handoff socket path budget",
        ));
    }
    Ok(root.to_path_buf())
}

fn unique_test_dir() -> support::HandoffFixture {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let explicit = std::env::var_os("HERDR_HANDOFF_FIXTURE_ROOT").map(PathBuf::from);
    let root =
        fixture_root(&std::env::temp_dir(), explicit.as_deref()).expect("valid short fixture root");
    loop {
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(n <= 9999, "fixture counter exceeded socket path budget");
        let base = root.join(format!("h{}-{n}", std::process::id()));
        match support::HandoffFixture::create(base) {
            Ok(fixture) => return fixture,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create exclusive fixture: {error}"),
        }
    }
}

fn spawn_owned_server(
    config_home: &Path,
    pair: portable_pty::PtyPair,
    cmd: CommandBuilder,
) -> SpawnedHerdr {
    support::set_handoff_starting(config_home, true);
    let child = match pair.slave.spawn_command(cmd) {
        Ok(child) => child,
        Err(error) => {
            support::set_handoff_starting(config_home, false);
            panic!("spawn fixture server: {error}");
        }
    };
    let mut spawned = SpawnedHerdr {
        _master: pair.master,
        child,
        identity: None,
        config_home: config_home.to_path_buf(),
    };
    let pid = spawned.child.process_id().expect("server PID");
    if std::env::var("HERDR_TEARDOWN_HELPER_MODE").as_deref() == Ok("hold-before-journal") {
        let birth = support::test_process_birth(pid).unwrap().unwrap();
        let report = std::env::var_os("HERDR_TEARDOWN_HELPER_REPORT").unwrap();
        fs::write(
            report,
            serde_json::to_vec(&[serde_json::json!({"pid": pid, "birth": birth})]).unwrap(),
        )
        .unwrap();
        hold_for_parent_failure();
    }
    if std::env::var("HERDR_TEARDOWN_HELPER_MODE").as_deref() == Ok("panic-before-registration") {
        let identity = support::settled_herdr_identity(pid).unwrap().unwrap();
        support::record_handoff_producer(config_home, &identity).expect("record startup producer");
        let birth = identity.birth;
        let report = std::env::var_os("HERDR_TEARDOWN_HELPER_REPORT").unwrap();
        fs::write(
            report,
            serde_json::to_vec(&[serde_json::json!({"pid": pid, "birth": birth})]).unwrap(),
        )
        .unwrap();
        panic!("injected failure while raw child startup is pending");
    }
    spawned.identity = Some(support::settled_herdr_identity(pid).unwrap().unwrap());
    support::register_handoff_producer(config_home, spawned.identity.as_ref().unwrap());
    register_spawned_herdr_pid(Some(pid));
    spawned
}

fn spawn_server(config_home: &Path, runtime_dir: &Path, api_socket: &Path) -> SpawnedHerdr {
    spawn_server_with_env(config_home, runtime_dir, api_socket, &[])
}

fn spawn_server_with_env(
    config_home: &Path,
    runtime_dir: &Path,
    api_socket: &Path,
    extra_env: &[(&str, &str)],
) -> SpawnedHerdr {
    fs::create_dir_all(config_home.join("herdr")).unwrap();
    fs::create_dir_all(runtime_dir).unwrap();
    fs::write(
        config_home.join("herdr/config.toml"),
        "onboarding = false\n",
    )
    .unwrap();

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_herdr"));
    cmd.arg("server");
    cmd.env("XDG_CONFIG_HOME", config_home);
    cmd.env("XDG_RUNTIME_DIR", runtime_dir);
    cmd.env("HERDR_SOCKET_PATH", api_socket);
    cmd.env(
        "HERDR_CLIENT_SOCKET_PATH",
        runtime_dir.join("herdr-client.sock"),
    );
    cmd.env("SHELL", "/bin/sh");
    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    support::register_handoff_data_dir(config_home, None);
    spawn_owned_server(config_home, pair, cmd)
}

fn spawn_named_session_server(
    config_home: &Path,
    runtime_dir: &Path,
    session_name: &str,
) -> SpawnedHerdr {
    fs::create_dir_all(config_home.join("herdr-dev")).unwrap();
    fs::create_dir_all(runtime_dir).unwrap();
    fs::write(
        config_home.join("herdr-dev/config.toml"),
        "onboarding = false\n",
    )
    .unwrap();

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_herdr"));
    cmd.arg("server");
    cmd.env("XDG_CONFIG_HOME", config_home);
    cmd.env("XDG_RUNTIME_DIR", runtime_dir);
    cmd.env("HERDR_SESSION", session_name);
    cmd.env_remove("HERDR_SOCKET_PATH");
    cmd.env_remove("HERDR_CLIENT_SOCKET_PATH");
    cmd.env("SHELL", "/bin/sh");

    support::register_handoff_data_dir(config_home, Some(session_name));
    spawn_owned_server(config_home, pair, cmd)
}

fn spawn_default_session_server(config_home: &Path, runtime_dir: &Path) -> SpawnedHerdr {
    fs::create_dir_all(config_home.join("herdr-dev")).unwrap();
    fs::create_dir_all(runtime_dir).unwrap();
    fs::write(
        config_home.join("herdr-dev/config.toml"),
        "onboarding = false\n",
    )
    .unwrap();

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_herdr"));
    cmd.arg("server");
    cmd.env("XDG_CONFIG_HOME", config_home);
    cmd.env("XDG_RUNTIME_DIR", runtime_dir);
    cmd.env("XDG_STATE_HOME", runtime_dir.join("state"));
    cmd.env_remove("HERDR_SESSION");
    cmd.env_remove("HERDR_SOCKET_PATH");
    cmd.env_remove("HERDR_CLIENT_SOCKET_PATH");
    cmd.env("SHELL", "/bin/sh");

    support::register_handoff_data_dir(config_home, None);
    spawn_owned_server(config_home, pair, cmd)
}

fn spawn_server_with_args_and_socket_env(
    config_home: &Path,
    runtime_dir: &Path,
    session_name: Option<&str>,
    api_socket_env: Option<&Path>,
    client_socket_env: Option<&Path>,
) -> SpawnedHerdr {
    fs::create_dir_all(config_home.join("herdr-dev")).unwrap();
    fs::create_dir_all(runtime_dir).unwrap();
    fs::write(
        config_home.join("herdr-dev/config.toml"),
        "onboarding = false\n",
    )
    .unwrap();

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_herdr"));
    if let Some(session_name) = session_name {
        cmd.arg("--session");
        cmd.arg(session_name);
    }
    cmd.arg("server");
    cmd.env("XDG_CONFIG_HOME", config_home);
    cmd.env("XDG_RUNTIME_DIR", runtime_dir);
    cmd.env_remove("HERDR_SESSION");
    if let Some(api_socket_env) = api_socket_env {
        cmd.env("HERDR_SOCKET_PATH", api_socket_env);
    } else {
        cmd.env_remove("HERDR_SOCKET_PATH");
    }
    if let Some(client_socket_env) = client_socket_env {
        cmd.env("HERDR_CLIENT_SOCKET_PATH", client_socket_env);
    } else {
        cmd.env_remove("HERDR_CLIENT_SOCKET_PATH");
    }
    cmd.env("SHELL", "/bin/sh");

    support::register_handoff_data_dir(config_home, session_name);
    spawn_owned_server(config_home, pair, cmd)
}

fn try_request(
    socket_path: &Path,
    request: serde_json::Value,
) -> Result<serde_json::Value, RequestError> {
    let mut stream = UnixStream::connect(socket_path).map_err(|err| RequestError {
        retryable: true,
        message: format!("connect {}: {err}", socket_path.display()),
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let request_text = request.to_string();
    stream
        .write_all(request_text.as_bytes())
        .map_err(|err| RequestError {
            retryable: true,
            message: format!("write request to {}: {err}", socket_path.display()),
        })?;
    stream.write_all(b"\n").map_err(|err| RequestError {
        retryable: true,
        message: format!("write newline to {}: {err}", socket_path.display()),
    })?;
    stream.flush().map_err(|err| RequestError {
        retryable: true,
        message: format!("flush request to {}: {err}", socket_path.display()),
    })?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|err| RequestError {
            retryable: true,
            message: format!("read response from {}: {err}", socket_path.display()),
        })?;
    if line.is_empty() {
        return Err(RequestError {
            retryable: true,
            message: format!(
                "empty response from {} for request {request_text}",
                socket_path.display()
            ),
        });
    }
    serde_json::from_str(&line).map_err(|err| RequestError {
        retryable: false,
        message: format!(
            "parse response from {} for request {request_text}: {err}; response was {line:?}",
            socket_path.display()
        ),
    })
}

fn request(socket_path: &Path, request: serde_json::Value) -> serde_json::Value {
    try_request(socket_path, request).unwrap_or_else(|err| panic!("{}", err.message))
}

fn assert_ok(response: serde_json::Value) {
    assert!(
        response.get("result").is_some(),
        "api request failed: {response}"
    );
}

fn wait_for_api(socket_path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut last_error = String::new();
    while Instant::now() < deadline {
        match try_request(
            socket_path,
            serde_json::json!({"id":"test:ping","method":"ping","params":{}}),
        ) {
            Ok(response) if response.get("result").is_some() => return,
            Ok(response) => panic!("api ping returned non-success response: {response}"),
            Err(err) if !err.retryable => panic!("{}", err.message),
            Err(err) => {
                last_error = err.message;
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!(
        "api did not become ready at {}; last error: {last_error}",
        socket_path.display()
    );
}

fn write_plugin_manifest(root: &Path, plugin_id: &str) {
    fs::create_dir_all(root).unwrap();
    fs::write(
        root.join("herdr-plugin.toml"),
        format!(
            r#"id = "{plugin_id}"
name = "Live handoff test"
version = "0.1.0"
min_herdr_version = "0.6.10"
platforms = ["linux", "macos", "windows"]
"#
        ),
    )
    .unwrap();
}

fn link_plugin(socket_path: &Path, root: &Path) {
    assert_ok(request(
        socket_path,
        serde_json::json!({
            "id": "test:plugin:link",
            "method": "plugin.link",
            "params": {"path": root, "enabled": true}
        }),
    ));
}

fn listed_plugin_ids(socket_path: &Path) -> Vec<String> {
    let response = request(
        socket_path,
        serde_json::json!({"id":"test:plugin:list","method":"plugin.list","params":{}}),
    );
    assert_ok(response.clone());
    response["result"]["plugins"]
        .as_array()
        .unwrap()
        .iter()
        .map(|plugin| plugin["plugin_id"].as_str().unwrap().to_string())
        .collect()
}

fn saved_plugin_ids(registry_path: &Path) -> Vec<String> {
    let mut ids =
        serde_json::from_str::<Vec<serde_json::Value>>(&fs::read_to_string(registry_path).unwrap())
            .unwrap()
            .into_iter()
            .map(|plugin| plugin["plugin_id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn wait_for_output(socket_path: &Path, pane_id: &str, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_text = String::new();
    let mut last_response = serde_json::Value::Null;
    while Instant::now() < deadline {
        let response = request(
            socket_path,
            serde_json::json!({
                "id": "test:pane:read",
                "method": "pane.read",
                "params": {
                    "pane_id": pane_id,
                    "source": "visible",
                    "lines": 20,
                    "format": "text",
                    "strip_ansi": true
                }
            }),
        );
        last_response = response.clone();
        let text = response["result"]["read"]["text"]
            .as_str()
            .unwrap_or_default();
        last_text = text.to_string();
        if text.contains(needle) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "pane output did not contain {needle:?}; last text was {last_text:?}; last response was {last_response}"
    );
}

fn wait_for_file_contains(path: &Path, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut last_text = String::new();
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(path) {
            last_text = text;
            if last_text.contains(needle) {
                return last_text;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "{} did not contain {needle:?}; last text was {last_text:?}",
        path.display()
    );
}

#[cfg(target_os = "linux")]
fn server_ptmx_fd_count(pid: u32) -> usize {
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        // ptmx master node: /dev/ptmx or /dev/pts/ptmx (devpts); slaves /dev/pts/<N> excluded.
        .filter(|target| target == Path::new("/dev/ptmx") || target == Path::new("/dev/pts/ptmx"))
        .count()
}

#[cfg(target_os = "macos")]
fn server_ptmx_fd_count(pid: u32) -> usize {
    let Ok(output) = std::process::Command::new("lsof")
        .args(["-nP", "-p", &pid.to_string()])
        .output()
    else {
        return 0;
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains("/dev/ptmx"))
        .count()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn wait_for_server_ptmx_fd_count(pid: u32, expected: usize, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut last_count = 0;
    while Instant::now() < deadline {
        last_count = server_ptmx_fd_count(pid);
        if last_count == expected {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("server pid {pid} had {last_count} ptmx master fds; expected {expected}");
}

fn wait_for_replacement_server_pid(runtime_dir: &Path, old_pid: u32, timeout: Duration) -> u32 {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let pids =
            support::handoff_replacement_pids(runtime_dir).expect("complete replacement inventory");
        if let Some(pid) = pids.into_iter().find(|pid| *pid != old_pid) {
            return pid;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!(
        "replacement server for {} did not appear",
        runtime_dir.display()
    );
}

fn unused_local_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_http_contains(port: u16, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut last_response = String::new();
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ =
                stream.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            last_response = response;
            if last_response.contains(needle) {
                return last_response;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "http server on port {port} did not return {needle:?}; last response was {last_response:?}"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn live_server_holds_one_pty_master_fd_per_pane() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");

    let spawned = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);
    let server_pid = spawned
        .child
        .process_id()
        .expect("test server should expose pid");
    wait_for_server_ptmx_fd_count(server_pid, 0, Duration::from_secs(5));

    let created = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace:create",
            "method": "workspace.create",
            "params": {"cwd": "/tmp", "focus": true}
        }),
    );
    let pane_id = created["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();
    wait_for_server_ptmx_fd_count(server_pid, 1, Duration::from_secs(5));

    let second = request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:split-second",
            "method": "pane.split",
            "params": {
                "target_pane_id": pane_id,
                "direction": "right",
                "focus": true
            }
        }),
    );
    assert_ok(second.clone());
    let second_pane_id = second["result"]["pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();
    wait_for_server_ptmx_fd_count(server_pid, 2, Duration::from_secs(5));

    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:split-third",
            "method": "pane.split",
            "params": {
                "target_pane_id": second_pane_id,
                "direction": "down",
                "focus": true
            }
        }),
    ));
    wait_for_server_ptmx_fd_count(server_pid, 3, Duration::from_secs(5));

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    let replacement_pid =
        wait_for_replacement_server_pid(&runtime_dir, server_pid, Duration::from_secs(10));
    wait_for_api(&api_socket, Duration::from_secs(10));
    wait_for_server_ptmx_fd_count(replacement_pid, 3, Duration::from_secs(5));

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    drop(spawned);
    cleanup_test_base(&base);
}

#[cfg(target_os = "linux")]
#[test]
fn live_handoff_unknown_pane_exit_preserves_session_on_shutdown() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");

    let spawned = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    let created = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace:create",
            "method": "workspace.create",
            "params": {"cwd": "/tmp", "focus": true}
        }),
    );
    let pane_id = created["result"]["root_pane"]["pane_id"]
        .as_str()
        .expect("root pane id")
        .to_string();
    let old_pid = spawned.child.process_id().expect("old server pid");

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    let replacement_pid =
        wait_for_replacement_server_pid(&runtime_dir, old_pid, Duration::from_secs(10));
    drop(spawned);
    wait_for_api(&api_socket, Duration::from_secs(10));

    let process_info = request(
        &api_socket,
        serde_json::json!({
            "id": "test:process-info",
            "method": "pane.process_info",
            "params": {"pane_id": pane_id}
        }),
    );
    let shell_pid = process_info["result"]["process_info"]["shell_pid"]
        .as_u64()
        .expect("shell pid") as libc::pid_t;
    assert_eq!(unsafe { libc::kill(shell_pid, libc::SIGHUP) }, 0);

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let panes = request(
            &api_socket,
            serde_json::json!({"id":"test:panes","method":"pane.list","params":{}}),
        );
        if panes["result"]["panes"]
            .as_array()
            .is_some_and(Vec::is_empty)
        {
            break;
        }
        assert!(Instant::now() < deadline, "handoff pane was not removed");
        thread::sleep(Duration::from_millis(20));
    }

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
    while Path::new(&format!("/proc/{replacement_pid}")).exists() {
        assert!(Instant::now() < deadline, "replacement server did not stop");
        thread::sleep(Duration::from_millis(20));
    }

    let session: serde_json::Value = serde_json::from_slice(
        &fs::read(config_home.join("herdr-dev/session.json")).expect("saved session"),
    )
    .expect("valid session json");
    assert_eq!(session["workspaces"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        session["workspaces"][0]["tabs"][0]["panes"]
            .as_object()
            .map(serde_json::Map::len),
        Some(1)
    );

    cleanup_test_base(&base);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn live_handoff_carries_more_panes_than_one_scm_rights_message() {
    const PANES: usize = 70;

    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");

    let spawned = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);
    let server_pid = spawned
        .child
        .process_id()
        .expect("test server should expose pid");

    let created = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace:create",
            "method": "workspace.create",
            "params": {"cwd": "/tmp", "focus": true}
        }),
    );
    let workspace_id = created["result"]["workspace"]["workspace_id"]
        .as_str()
        .unwrap()
        .to_string();

    // One pane per tab keeps the layout shallow, so this exercises the fd
    // transfer rather than the depth of a single split tree.
    for index in 1..PANES {
        assert_ok(request(
            &api_socket,
            serde_json::json!({
                "id": format!("test:tab:create-{index}"),
                "method": "tab.create",
                "params": {"workspace_id": workspace_id, "focus": false}
            }),
        ));
    }
    wait_for_server_ptmx_fd_count(server_pid, PANES, Duration::from_secs(60));

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    let replacement_pid =
        wait_for_replacement_server_pid(&runtime_dir, server_pid, Duration::from_secs(30));
    wait_for_api(&api_socket, Duration::from_secs(30));
    wait_for_server_ptmx_fd_count(replacement_pid, PANES, Duration::from_secs(30));

    let panes = request(
        &api_socket,
        serde_json::json!({"id":"test:pane:list","method":"pane.list","params":{}}),
    );
    assert_eq!(
        panes["result"]["panes"].as_array().map(Vec::len),
        Some(PANES),
        "replacement server should report every pane after handoff"
    );

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    drop(spawned);
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_preserves_named_session_socket_paths() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let session_dir = config_home.join("herdr-dev/sessions/work");
    let api_socket = session_dir.join("herdr.sock");
    let client_socket = session_dir.join("herdr-client.sock");

    let spawned = spawn_named_session_server(&config_home, &runtime_dir, "work");
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    drop(spawned);
    wait_for_api(&api_socket, Duration::from_secs(10));
    wait_for_socket(&client_socket, Duration::from_secs(5));
    assert!(
        !config_home.join("herdr-dev/herdr.sock").exists(),
        "named handoff unexpectedly bound the default session API socket"
    );

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_ignores_leaked_default_socket_env_for_named_session() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let default_session_dir = config_home.join("herdr-dev");
    let default_api_socket = default_session_dir.join("herdr.sock");
    let default_client_socket = default_session_dir.join("herdr-client.sock");
    let work_session_dir = config_home.join("herdr-dev/sessions/work");
    let work_api_socket = work_session_dir.join("herdr.sock");
    let work_client_socket = work_session_dir.join("herdr-client.sock");

    let default_spawned = spawn_default_session_server(&config_home, &runtime_dir);
    wait_for_socket(&default_api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    let work_spawned = spawn_server_with_args_and_socket_env(
        &config_home,
        &runtime_dir,
        Some("work"),
        Some(&default_api_socket),
        Some(&default_client_socket),
    );
    wait_for_socket(&work_api_socket, Duration::from_secs(10));

    assert_ok(request(
        &work_api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    drop(work_spawned);
    wait_for_api(&default_api_socket, Duration::from_secs(10));
    wait_for_api(&work_api_socket, Duration::from_secs(10));
    wait_for_socket(&work_client_socket, Duration::from_secs(5));

    let _ = request(
        &work_api_socket,
        serde_json::json!({"id":"test:stop-work","method":"server.stop","params":{}}),
    );
    let _ = request(
        &default_api_socket,
        serde_json::json!({"id":"test:stop-default","method":"server.stop","params":{}}),
    );
    drop(default_spawned);
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_preserves_client_socket_env_without_api_socket_env() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = config_home.join("herdr-dev/herdr.sock");
    let client_socket = runtime_dir.join("custom-client.sock");

    let spawned = spawn_server_with_args_and_socket_env(
        &config_home,
        &runtime_dir,
        None,
        None,
        Some(&client_socket),
    );
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_socket(&client_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    drop(spawned);
    wait_for_api(&api_socket, Duration::from_secs(10));
    wait_for_socket(&client_socket, Duration::from_secs(5));

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_preserves_installed_plugins() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = config_home.join("herdr-dev/herdr.sock");
    let registry_path = config_home.join("herdr-dev/plugins.json");
    let existing_plugin = base.join("plugins/existing");
    let added_plugin = base.join("plugins/added");
    write_plugin_manifest(&existing_plugin, "test.live-handoff-existing");
    write_plugin_manifest(&added_plugin, "test.live-handoff-added");

    let spawned = spawn_default_session_server(&config_home, &runtime_dir);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    link_plugin(&api_socket, &existing_plugin);
    assert_eq!(
        listed_plugin_ids(&api_socket),
        ["test.live-handoff-existing"]
    );

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    drop(spawned);
    wait_for_api(&api_socket, Duration::from_secs(10));

    assert_eq!(
        listed_plugin_ids(&api_socket),
        ["test.live-handoff-existing"]
    );
    link_plugin(&api_socket, &added_plugin);
    assert_eq!(
        saved_plugin_ids(&registry_path),
        ["test.live-handoff-added", "test.live-handoff-existing"]
    );

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_preserves_pane_process_io() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let marker = base.join("child.pid");
    let second_marker = base.join("second-child.pid");
    let hup_marker = base.join("hup");
    let second_hup_marker = base.join("second-hup");
    let received_marker = base.join("received");
    let second_received_marker = base.join("second-received");

    let spawned = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    let created = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace:create",
            "method": "workspace.create",
            "params": {"cwd": "/tmp", "focus": true}
        }),
    );
    let pane_id = created["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();
    let split = request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:split",
            "method": "pane.split",
            "params": {
                "target_pane_id": pane_id,
                "direction": "right",
                "focus": false
            }
        }),
    );
    assert_ok(split.clone());
    let second_pane_id = split["result"]["pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();

    let command = format!(
        "sh -c 'echo READY $$ > {}; trap \"echo HUP >> {}\" HUP; while read line; do echo got:$line; echo got:$line >> {}; done'",
        marker.display(),
        hup_marker.display(),
        received_marker.display()
    );
    let second_command = format!(
        "sh -c 'echo SECOND_READY $$ > {}; trap \"echo HUP >> {}\" HUP; while read line; do echo second:$line; echo second:$line >> {}; done'",
        second_marker.display(),
        second_hup_marker.display(),
        second_received_marker.display()
    );
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:run",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": command, "keys": ["Enter"]}
        }),
    ));
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:second-pane:run",
            "method": "pane.send_input",
            "params": {"pane_id": second_pane_id, "text": second_command, "keys": ["Enter"]}
        }),
    ));
    support::wait_for_file(&marker, Duration::from_secs(5));
    support::wait_for_file(&second_marker, Duration::from_secs(5));
    let pid_text = fs::read_to_string(&marker).unwrap();
    let child_pid: u32 = pid_text.split_whitespace().last().unwrap().parse().unwrap();
    let second_pid_text = fs::read_to_string(&second_marker).unwrap();
    let second_child_pid: u32 = second_pid_text
        .split_whitespace()
        .last()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(unsafe { libc::kill(child_pid as libc::pid_t, 0) }, 0);
    assert_eq!(unsafe { libc::kill(second_child_pid as libc::pid_t, 0) }, 0);

    let endpoint_generation = support::CURRENT_ENDPOINT_PROTOCOL_GENERATION;
    let mut client_stream = UnixStream::connect(&client_socket).unwrap();
    let (server_generation, error) =
        client_shell_handshake(&mut client_stream, endpoint_generation, 54, 23).unwrap();
    assert_eq!(server_generation, endpoint_generation);
    assert!(error.is_none(), "client shell handshake failed: {error:?}");
    assert!(
        wait_for_message_variant(
            &mut client_stream,
            Duration::from_secs(5),
            SERVER_MESSAGE_ENDPOINT_CONTROL,
        )
        .unwrap(),
        "client shell should receive a complete snapshot before handoff"
    );

    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:before-log",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": "before_replay", "keys": ["Enter"]}
        }),
    ));
    wait_for_output(&api_socket, &pane_id, "got:before_replay");

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    assert!(
        wait_for_message_variant(
            &mut client_stream,
            Duration::from_secs(5),
            SERVER_MESSAGE_SERVER_SHUTDOWN,
        )
        .unwrap(),
        "connected client shell should receive live-handoff shutdown"
    );
    drop(spawned);
    thread::sleep(Duration::from_millis(300));
    wait_for_api(&api_socket, Duration::from_secs(10));
    wait_for_socket(&client_socket, Duration::from_secs(5));
    assert_eq!(unsafe { libc::kill(child_pid as libc::pid_t, 0) }, 0);
    assert_eq!(unsafe { libc::kill(second_child_pid as libc::pid_t, 0) }, 0);
    assert!(
        !hup_marker.exists(),
        "pane process received HUP during handoff"
    );
    assert!(
        !second_hup_marker.exists(),
        "second pane process received HUP during handoff"
    );
    wait_for_output(&api_socket, &pane_id, "got:before_replay");

    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:send",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": "after-handoff", "keys": ["Enter"]}
        }),
    ));
    wait_for_file_contains(
        &received_marker,
        "got:after-handoff",
        Duration::from_secs(5),
    );
    wait_for_output(&api_socket, &pane_id, "got:after-handoff");
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:second-pane:send",
            "method": "pane.send_input",
            "params": {"pane_id": second_pane_id, "text": "after-handoff-second", "keys": ["Enter"]}
        }),
    ));
    wait_for_file_contains(
        &second_received_marker,
        "second:after-handoff-second",
        Duration::from_secs(5),
    );
    wait_for_output(&api_socket, &second_pane_id, "second:after-handoff-sec");

    let mut reattached_shell = UnixStream::connect(&client_socket).unwrap();
    let (server_generation, error) = client_shell_handshake(
        &mut reattached_shell,
        support::CURRENT_ENDPOINT_PROTOCOL_GENERATION,
        54,
        23,
    )
    .unwrap();
    assert_eq!(
        server_generation,
        support::CURRENT_ENDPOINT_PROTOCOL_GENERATION
    );
    assert!(error.is_none(), "reattached client shell failed: {error:?}");
    wait_for_client_shell_bootstrap(&mut reattached_shell, Duration::from_secs(5))
        .expect("fresh client shell should receive restored snapshot before pane content");

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    let _ = client_socket;
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_preserves_keyboard_protocol_for_client_input() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let script = base.join("read-raw.py");
    let ready_marker = base.join("keyboard-ready");
    let received_marker = base.join("keyboard-received");

    fs::create_dir_all(&base).unwrap();
    fs::write(
        &script,
        format!(
            r#"import os
import pathlib
import select
import sys
import tty

sys.stdout.buffer.write(b"\x1b[>5u")
sys.stdout.flush()
pathlib.Path({ready:?}).write_text("ready")
tty.setraw(sys.stdin.fileno())
ready_fds, _, _ = select.select([sys.stdin.fileno()], [], [], 5)
data = os.read(sys.stdin.fileno(), 32) if ready_fds else b""
pathlib.Path({received:?}).write_text(data.hex())
"#,
            ready = ready_marker.display().to_string(),
            received = received_marker.display().to_string()
        ),
    )
    .unwrap();

    let spawned = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    let created = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace:create",
            "method": "workspace.create",
            "params": {"cwd": "/tmp", "focus": true}
        }),
    );
    let pane_id = created["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:run",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": format!("python3 {}", script.display()), "keys": ["Enter"]}
        }),
    ));
    support::wait_for_file(&ready_marker, Duration::from_secs(5));

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    drop(spawned);
    wait_for_api(&api_socket, Duration::from_secs(10));
    wait_for_socket(&client_socket, Duration::from_secs(5));

    let mut client_stream = UnixStream::connect(&client_socket).unwrap();
    let (server_generation, error) = client_shell_handshake(
        &mut client_stream,
        support::CURRENT_ENDPOINT_PROTOCOL_GENERATION,
        54,
        23,
    )
    .unwrap();
    assert_eq!(
        server_generation,
        support::CURRENT_ENDPOINT_PROTOCOL_GENERATION
    );
    assert!(error.is_none(), "client shell handshake failed: {error:?}");
    wait_for_client_shell_bootstrap(&mut client_stream, Duration::from_secs(5))
        .expect("client shell should receive restored state before sending input");
    send_client_shell_shift_enter(&mut client_stream, &pane_id).unwrap();

    wait_for_file_contains(&received_marker, "1b5b31333b3275", Duration::from_secs(5));

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_preserves_modify_other_keys_for_client_input() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let script = base.join("read-raw.py");
    let ready_marker = base.join("modify-ready");
    let received_marker = base.join("modify-received");

    fs::create_dir_all(&base).unwrap();
    fs::write(
        &script,
        format!(
            r#"import os
import pathlib
import select
import sys
import tty

sys.stdout.buffer.write(b"\x1b[>4;2m")
sys.stdout.flush()
pathlib.Path({ready:?}).write_text("ready")
tty.setraw(sys.stdin.fileno())
ready_fds, _, _ = select.select([sys.stdin.fileno()], [], [], 5)
data = os.read(sys.stdin.fileno(), 32) if ready_fds else b""
pathlib.Path({received:?}).write_text(data.hex())
"#,
            ready = ready_marker.display().to_string(),
            received = received_marker.display().to_string()
        ),
    )
    .unwrap();

    let spawned = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    let created = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace:create",
            "method": "workspace.create",
            "params": {"cwd": "/tmp", "focus": true}
        }),
    );
    let pane_id = created["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:run",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": format!("python3 {}", script.display()), "keys": ["Enter"]}
        }),
    ));
    support::wait_for_file(&ready_marker, Duration::from_secs(5));

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    drop(spawned);
    wait_for_api(&api_socket, Duration::from_secs(10));
    wait_for_socket(&client_socket, Duration::from_secs(5));

    let mut client_stream = UnixStream::connect(&client_socket).unwrap();
    let (server_generation, error) = client_shell_handshake(
        &mut client_stream,
        support::CURRENT_ENDPOINT_PROTOCOL_GENERATION,
        54,
        23,
    )
    .unwrap();
    assert_eq!(
        server_generation,
        support::CURRENT_ENDPOINT_PROTOCOL_GENERATION
    );
    assert!(error.is_none(), "client shell handshake failed: {error:?}");
    wait_for_client_shell_bootstrap(&mut client_stream, Duration::from_secs(5))
        .expect("client shell should receive restored state before sending input");
    send_client_shell_shift_enter(&mut client_stream, &pane_id).unwrap();

    wait_for_file_contains(
        &received_marker,
        "1b5b32373b323b31337e",
        Duration::from_secs(5),
    );

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_accepts_canonical_pane_id_from_child_env() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let pane_id_marker = base.join("pane-id");

    let spawned = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    let created = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace:create",
            "method": "workspace.create",
            "params": {"cwd": "/tmp", "focus": true}
        }),
    );
    let pane_id = created["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:print-id",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": format!("printf '%s' \"$HERDR_PANE_ID\" > {}", pane_id_marker.display()), "keys": ["Enter"]}
        }),
    ));
    let old_pane_id = wait_for_file_contains(&pane_id_marker, &pane_id, Duration::from_secs(5));
    assert!(
        old_pane_id == pane_id,
        "unexpected pane id from env: {old_pane_id:?}"
    );

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    drop(spawned);
    wait_for_api(&api_socket, Duration::from_secs(10));

    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:old-pane-report",
            "method": "pane.report_agent",
            "params": {
                "pane_id": old_pane_id,
                "source": "handoff-test",
                "agent": "pi",
                "state": "working"
            }
        }),
    ));
    let agents = request(
        &api_socket,
        serde_json::json!({"id":"test:agent-list","method":"agent.list","params":{}}),
    );
    let found = agents["result"]["agents"]
        .as_array()
        .unwrap()
        .iter()
        .any(|agent| {
            agent["agent"].as_str() == Some("pi")
                && agent["agent_status"].as_str() == Some("working")
        });
    assert!(
        found,
        "old pane id report did not update restored pane: {agents}"
    );

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_keeps_unmanaged_agent_name_bound_to_saved_session() {
    use std::os::unix::fs::PermissionsExt;

    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let old_session = base.join("old-session.jsonl");
    let new_session = base.join("new-session.jsonl");
    let started_marker = base.join("agent-started");
    let fake_pi = base.join("pi");
    fs::create_dir_all(&base).unwrap();
    fs::write(
        &fake_pi,
        format!(
            "#!/bin/sh\nexport HERDR_AGENT=pi\necho started > {}\n/bin/sleep 30\n:\n",
            started_marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_pi, fs::Permissions::from_mode(0o755)).unwrap();

    let spawned = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);
    let created = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace:create",
            "method": "workspace.create",
            "params": {"cwd": "/tmp", "focus": true}
        }),
    );
    let pane_id = created["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:start-agent",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": fake_pi, "keys": ["Enter"]}
        }),
    ));
    support::wait_for_file(&started_marker, Duration::from_secs(5));
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:agent:session",
            "method": "pane.report_agent_session",
            "params": {
                "pane_id": pane_id,
                "source": "herdr:pi",
                "agent": "pi",
                "seq": 1,
                "agent_session_path": old_session,
                "session_start_source": "startup"
            }
        }),
    ));
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:agent:report",
            "method": "pane.report_agent",
            "params": {
                "pane_id": pane_id,
                "source": "herdr:pi",
                "agent": "pi",
                "state": "idle",
                "seq": 2,
                "agent_session_path": old_session
            }
        }),
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let response = request(
            &api_socket,
            serde_json::json!({
                "id": "test:agent:wait-for-process",
                "method": "agent.get",
                "params": {"target": pane_id}
            }),
        );
        if response.get("result").is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "agent process was not detected: {response}"
        );
        thread::sleep(Duration::from_millis(25));
    }
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:agent:rename",
            "method": "agent.rename",
            "params": {"target": pane_id, "name": "reviewer"}
        }),
    ));

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    drop(spawned);
    wait_for_api(&api_socket, Duration::from_secs(10));

    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:agent:new-session",
            "method": "pane.report_agent_session",
            "params": {
                "pane_id": pane_id,
                "source": "herdr:pi",
                "agent": "pi",
                "seq": 3,
                "agent_session_path": new_session,
                "session_start_source": "new"
            }
        }),
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let old_name = request(
            &api_socket,
            serde_json::json!({
                "id": "test:agent:get-old-name",
                "method": "agent.get",
                "params": {"target": "reviewer"}
            }),
        );
        if old_name["error"]["code"] == "agent_not_found" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "old session alias was not cleared: {old_name}"
        );
        thread::sleep(Duration::from_millis(25));
    }

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_keeps_agent_started_pane_after_agent_exits() {
    use std::os::unix::fs::PermissionsExt;

    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let started_marker = base.join("agent-started");
    let exited_marker = base.join("agent-exited");
    let ready_marker = base.join("shell-ready");
    let shell_marker = base.join("shell-after-agent");
    let bin = base.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let delayed_shell = bin.join("delayed-shell");
    fs::write(&delayed_shell, "#!/bin/sh\n/bin/sleep 0.4\nexec /bin/sh\n").unwrap();
    fs::set_permissions(&delayed_shell, fs::Permissions::from_mode(0o755)).unwrap();
    let fake_pi = bin.join("pi");
    fs::write(
        &fake_pi,
        format!(
            "#!/bin/sh\nexport HERDR_AGENT=pi\necho started > {}\n/bin/sleep 1\necho exited > {}\n",
            started_marker.display(),
            exited_marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_pi, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:/bin:/usr/bin", bin.display());

    let spawned = spawn_server_with_env(
        &config_home,
        &runtime_dir,
        &api_socket,
        &[
            ("PATH", path.as_str()),
            ("SHELL", delayed_shell.to_str().unwrap()),
        ],
    );
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);
    let workspace = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace-create",
            "method": "workspace.create",
            "params": { "cwd": "/tmp", "focus": false }
        }),
    );
    assert_ok(workspace.clone());
    let pane_id = workspace["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();

    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:shell-ready",
            "method": "pane.send_input",
            "params": {
                "pane_id": pane_id,
                "text": format!("printf ready > {}", ready_marker.display()),
                "keys": ["Enter"]
            }
        }),
    ));
    // Creation acknowledges the PTY, not an idle interactive shell. A real
    // shell command must execute before this raw agent.start request.
    support::wait_for_file(&ready_marker, Duration::from_secs(5));

    let started = request(
        &api_socket,
        serde_json::json!({
            "id": "test:agent-start",
            "method": "agent.start",
            "params": {
                "name": "handoff-agent",
                "kind": "pi",
                "pane_id": pane_id,
                "timeout_ms": 5000
            }
        }),
    );
    assert_ok(started);
    support::wait_for_file(&started_marker, Duration::from_secs(5));

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    drop(spawned);
    wait_for_api(&api_socket, Duration::from_secs(10));
    support::wait_for_file(&exited_marker, Duration::from_secs(5));
    thread::sleep(Duration::from_millis(300));

    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:shell-after-agent",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": format!("echo alive > {}", shell_marker.display()), "keys": ["Enter"]}
        }),
    ));
    support::wait_for_file(&shell_marker, Duration::from_secs(5));

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_keeps_shell_pane_after_foreground_process_exits() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let started_marker = base.join("foreground-started");
    let exited_marker = base.join("foreground-exited");
    let shell_marker = base.join("shell-after-foreground");

    let spawned = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    let created = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace:create",
            "method": "workspace.create",
            "params": {"cwd": "/tmp", "focus": true}
        }),
    );
    let pane_id = created["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();
    let command = format!(
        "sh -c 'echo started > {}; sleep 1; echo exited > {}'",
        started_marker.display(),
        exited_marker.display()
    );
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:run-foreground",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": command, "keys": ["Enter"]}
        }),
    ));
    support::wait_for_file(&started_marker, Duration::from_secs(5));

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    drop(spawned);
    wait_for_api(&api_socket, Duration::from_secs(10));
    support::wait_for_file(&exited_marker, Duration::from_secs(5));

    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:shell-after-foreground",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": format!("echo alive > {}", shell_marker.display()), "keys": ["Enter"]}
        }),
    ));
    support::wait_for_file(&shell_marker, Duration::from_secs(5));

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_preserves_python_http_server() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let web_root = base.join("web");
    fs::create_dir_all(&web_root).unwrap();
    fs::write(
        web_root.join("index.html"),
        "hello-from-python-before-and-after",
    )
    .unwrap();
    let port = unused_local_port();

    let spawned = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    let created = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace:create",
            "method": "workspace.create",
            "params": {"cwd": web_root, "focus": true}
        }),
    );
    let pane_id = created["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();

    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:run-python",
            "method": "pane.send_input",
            "params": {
                "pane_id": pane_id,
                "text": format!("python3 -m http.server {port} --bind 127.0.0.1"),
                "keys": ["Enter"]
            }
        }),
    ));
    wait_for_http_contains(
        port,
        "hello-from-python-before-and-after",
        Duration::from_secs(10),
    );

    assert_ok(request(
        &api_socket,
        serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
    ));
    drop(spawned);
    wait_for_api(&api_socket, Duration::from_secs(10));
    wait_for_http_contains(
        port,
        "hello-from-python-before-and-after",
        Duration::from_secs(10),
    );

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    let _ = client_socket;
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_preserves_http_servers_across_multiple_sessions() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let sessions = [
        (None, config_home.join("herdr-dev/herdr.sock")),
        (
            Some("work"),
            config_home.join("herdr-dev/sessions/work/herdr.sock"),
        ),
    ];
    let mut spawned = Vec::new();
    let mut ports = Vec::new();

    for (session_name, api_socket) in &sessions {
        let web_root = base.join(format!("web-{}", session_name.unwrap_or("default")));
        fs::create_dir_all(&web_root).unwrap();
        fs::write(
            web_root.join("index.html"),
            format!("hello-from-{}", session_name.unwrap_or("default")),
        )
        .unwrap();
        let port = unused_local_port();
        let server = if let Some(session_name) = session_name {
            spawn_named_session_server(&config_home, &runtime_dir, session_name)
        } else {
            spawn_default_session_server(&config_home, &runtime_dir)
        };
        wait_for_socket(api_socket, Duration::from_secs(10));
        let created = request(
            api_socket,
            serde_json::json!({
                "id": "test:workspace:create",
                "method": "workspace.create",
                "params": {"cwd": web_root, "focus": true}
            }),
        );
        let pane_id = created["result"]["root_pane"]["pane_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ok(request(
            api_socket,
            serde_json::json!({
                "id": "test:pane:run-python",
                "method": "pane.send_input",
                "params": {
                    "pane_id": pane_id,
                    "text": format!("python3 -m http.server {port} --bind 127.0.0.1"),
                    "keys": ["Enter"]
                }
            }),
        ));
        wait_for_http_contains(
            port,
            &format!("hello-from-{}", session_name.unwrap_or("default")),
            Duration::from_secs(10),
        );
        spawned.push(server);
        ports.push((port, session_name.unwrap_or("default").to_string()));
    }
    register_runtime_dir(&runtime_dir);

    for (_session_name, api_socket) in &sessions {
        assert_ok(request(
            api_socket,
            serde_json::json!({"id":"test:handoff","method":"server.live_handoff","params":{}}),
        ));
    }
    drop(spawned);

    for (_session_name, api_socket) in &sessions {
        wait_for_api(api_socket, Duration::from_secs(10));
    }
    for (port, label) in ports {
        wait_for_http_contains(
            port,
            &format!("hello-from-{label}"),
            Duration::from_secs(10),
        );
    }

    for (_session_name, api_socket) in &sessions {
        let _ = request(
            api_socket,
            serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
        );
    }
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_bad_expected_protocol_rolls_back_old_server() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let marker = base.join("child.pid");
    let received_marker = base.join("received");

    let spawned = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    let created = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace:create",
            "method": "workspace.create",
            "params": {"cwd": "/tmp", "focus": true}
        }),
    );
    let pane_id = created["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();
    let command = format!(
        "sh -c 'echo READY $$ > {}; while read line; do echo got:$line; echo got:$line >> {}; done'",
        marker.display(),
        received_marker.display()
    );
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:run",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": command, "keys": ["Enter"]}
        }),
    ));
    support::wait_for_file(&marker, Duration::from_secs(5));
    let pid_text = fs::read_to_string(&marker).unwrap();
    let child_pid: u32 = pid_text.split_whitespace().last().unwrap().parse().unwrap();

    let failed = request(
        &api_socket,
        serde_json::json!({
            "id": "test:bad-handoff",
            "method": "server.live_handoff",
            "params": {"expected_protocol": 999999}
        }),
    );
    assert!(
        failed.get("error").is_some(),
        "bad protocol handoff should fail: {failed}"
    );
    wait_for_api(&api_socket, Duration::from_secs(5));
    assert_eq!(unsafe { libc::kill(child_pid as libc::pid_t, 0) }, 0);

    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:send-after-failed-handoff",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": "after-failed-handoff", "keys": ["Enter"]}
        }),
    ));
    wait_for_file_contains(
        &received_marker,
        "got:after-failed-handoff",
        Duration::from_secs(5),
    );
    wait_for_output(&api_socket, &pane_id, "got:after-failed-handoff");

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    drop(spawned);
    cleanup_test_base(&base);
}

fn live_handoff_import_failure_rolls_back_old_server_at(failure_point: &str) {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let marker = base.join("child.pid");
    let received_marker = base.join("received");

    let spawned = spawn_server_with_env(
        &config_home,
        &runtime_dir,
        &api_socket,
        &[("HERDR_TEST_HANDOFF_IMPORT_FAIL", failure_point)],
    );
    wait_for_socket(&api_socket, Duration::from_secs(10));
    register_runtime_dir(&runtime_dir);

    let created = request(
        &api_socket,
        serde_json::json!({
            "id": "test:workspace:create",
            "method": "workspace.create",
            "params": {"cwd": "/tmp", "focus": true}
        }),
    );
    let pane_id = created["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap()
        .to_string();
    let command = format!(
        "sh -c 'echo READY $$ > {}; while read line; do echo got:$line; echo got:$line >> {}; done'",
        marker.display(),
        received_marker.display()
    );
    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:run",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": command, "keys": ["Enter"]}
        }),
    ));
    support::wait_for_file(&marker, Duration::from_secs(5));
    let pid_text = fs::read_to_string(&marker).unwrap();
    let child_pid: u32 = pid_text.split_whitespace().last().unwrap().parse().unwrap();

    let failed = request(
        &api_socket,
        serde_json::json!({"id":"test:handoff-fail","method":"server.live_handoff","params":{}}),
    );
    assert!(
        failed.get("error").is_some(),
        "{failure_point} handoff should fail: {failed}"
    );
    wait_for_api(&api_socket, Duration::from_secs(10));
    wait_for_socket(&client_socket, Duration::from_secs(5));
    assert_eq!(unsafe { libc::kill(child_pid as libc::pid_t, 0) }, 0);

    assert_ok(request(
        &api_socket,
        serde_json::json!({
            "id": "test:pane:send-after-import-failure",
            "method": "pane.send_input",
            "params": {"pane_id": pane_id, "text": failure_point, "keys": ["Enter"]}
        }),
    ));
    wait_for_file_contains(
        &received_marker,
        &format!("got:{failure_point}"),
        Duration::from_secs(5),
    );

    let _ = request(
        &api_socket,
        serde_json::json!({"id":"test:stop","method":"server.stop","params":{}}),
    );
    drop(spawned);
    cleanup_test_base(&base);
}

#[test]
fn live_handoff_after_restored_failure_rolls_back_old_server() {
    live_handoff_import_failure_rolls_back_old_server_at("after_restored");
}

#[test]
fn teardown_normal_handoff_leaves_no_server() {
    let _lock = test_lock();
    for named in [false, true] {
        let base = unique_test_dir();
        let config = base.join("config");
        let runtime = base.join("runtime");
        let socket = if named {
            config.join("herdr-dev/sessions/work/herdr.sock")
        } else {
            runtime.join("herdr.sock")
        };
        let server = if named {
            spawn_named_session_server(&config, &runtime, "work")
        } else {
            spawn_server(&config, &runtime, &socket)
        };
        let original = server.identity.as_ref().unwrap().clone();
        wait_for_socket(&socket, Duration::from_secs(10));
        assert_ok(request(
            &socket,
            serde_json::json!({"id":"teardown:handoff","method":"server.live_handoff","params":{}}),
        ));
        let replacement =
            wait_for_replacement_server_pid(&runtime, original.pid, Duration::from_secs(5));
        let replacement = support::test_process_identity(replacement)
            .unwrap()
            .unwrap();
        assert_ne!(original.pid, replacement.pid);
        drop(server);
        base.finish().unwrap();
        for identity in [original, replacement] {
            assert_ne!(
                support::test_process_birth(identity.pid).unwrap(),
                Some(identity.birth),
                "server {} survived fixture cleanup",
                identity.pid
            );
        }
    }
}

// Dedicated child entry point: ordinary test discovery is a harmless no-op.
#[test]
fn teardown_helper_process() {
    let Ok(mode) = std::env::var("HERDR_TEARDOWN_HELPER_MODE") else {
        return;
    };
    let report = std::env::var_os("HERDR_TEARDOWN_HELPER_REPORT").unwrap();
    if mode == "term-resistant" {
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
        fs::write(report, "ready").unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        panic!("TERM-resistant helper self-deadline reached without expected KILL");
    }
    assert!(matches!(
        mode.as_str(),
        "panic-after-handoff"
            | "panic-before-readiness"
            | "panic-before-response"
            | "panic-before-registration"
            | "hold-after-handoff"
            | "hold-before-readiness"
            | "hold-before-journal"
    ));
    let base = support::HandoffFixture::borrow_from_parent(
        PathBuf::from(std::env::var_os("HERDR_TEARDOWN_FIXTURE").unwrap()),
        std::env::var("HERDR_TEARDOWN_PARENT")
            .unwrap()
            .parse()
            .unwrap(),
    )
    .unwrap();
    let config = base.join("config");
    let runtime = base.join("runtime");
    let socket = runtime.join("herdr.sock");
    let server = spawn_server(&config, &runtime, &socket);
    let original = server.identity.as_ref().unwrap().clone();
    let mut identities = vec![serde_json::json!({"pid": original.pid, "birth": original.birth})];
    fs::write(&report, serde_json::to_vec(&identities).unwrap()).unwrap();
    if mode == "hold-before-readiness" {
        hold_for_parent_failure();
    }
    if mode == "panic-before-readiness" {
        panic!("injected failure before readiness assertion");
    }
    wait_for_socket(&socket, Duration::from_secs(10));
    if mode == "panic-before-response" {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        writeln!(
            stream,
            "{}",
            serde_json::json!({"id":"teardown:handoff","method":"server.live_handoff","params":{}})
        )
        .unwrap();
        // Deliberately leave the response unread, but synchronize on the import
        // identity so the failure is not a timing-only sleep.
    } else {
        assert_ok(request(
            &socket,
            serde_json::json!({"id":"teardown:handoff","method":"server.live_handoff","params":{}}),
        ));
    }
    let replacement =
        wait_for_replacement_server_pid(&runtime, original.pid, Duration::from_secs(5));
    let replacement = support::test_process_identity(replacement)
        .unwrap()
        .unwrap();
    identities.push(serde_json::json!({"pid": replacement.pid, "birth": replacement.birth}));
    fs::write(report, serde_json::to_vec(&identities).unwrap()).unwrap();
    if mode == "hold-after-handoff" {
        hold_for_parent_failure();
    }
    panic!("injected failure after replacement identity observed");
}

fn hold_for_parent_failure() -> ! {
    let end = Instant::now() + Duration::from_secs(15);
    while Instant::now() < end {
        thread::sleep(Duration::from_millis(20));
    }
    panic!("parent failed to exercise bounded early-failure cleanup");
}

struct TeardownChild(std::process::Child, Option<support::HandoffFixture>);
impl TeardownChild {
    fn capture_before_reap(&mut self) -> std::io::Result<bool> {
        if self.1.is_none() || self.0.try_wait()?.is_some() {
            return Ok(false);
        }
        // try_wait has not reaped: this handle still owns the positive child PID.
        let pid = self.0.id() as i32;
        if unsafe { libc::kill(pid, libc::SIGSTOP) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            let mut status = 0;
            let waited =
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::WUNTRACED) };
            if waited == pid {
                if libc::WIFSTOPPED(status) {
                    break;
                }
                // A process that exited before STOP cannot create another child;
                // keep any pending-startup marker because ancestry is now lost.
                return Ok(false);
            }
            if waited < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if Instant::now() >= end {
                return Err(std::io::Error::other(
                    "nested helper did not stop before inventory",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.1
            .as_ref()
            .unwrap()
            .capture_stopped_helper_children(self.0.id())?;
        Ok(true)
    }

    fn reap_helper(&mut self) -> bool {
        match self.0.try_wait() {
            Ok(Some(_)) => return true,
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return true,
            Err(error) => {
                eprintln!("nested child inspection unresolved: {error}");
                return false;
            }
            Ok(None) => {}
        }
        // No preceding reap: this direct child's handle still owns its PID.
        let _ = self.0.kill();
        let end = Instant::now() + Duration::from_secs(2);
        while Instant::now() < end {
            match self.0.try_wait() {
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Ok(Some(_)) => return true,
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return true,
                Err(error) => {
                    eprintln!("nested child reaping unresolved: {error}");
                    return false;
                }
            }
        }
        eprintln!("nested child {} did not reap before deadline", self.0.id());
        false
    }
}

impl Drop for TeardownChild {
    fn drop(&mut self) {
        let captured = self.capture_before_reap();
        if !self.reap_helper() {
            if thread::panicking() {
                eprintln!("nested helper unresolved; fixture ownership retained");
            } else {
                panic!("nested helper unresolved; fixture ownership retained");
            }
            return;
        }
        if let Some(fixture) = &self.1 {
            let capture_error = match captured {
                Ok(true) => fixture.clear_reaped_helper_startup().err(),
                Ok(false) => None,
                Err(error) => Some(error),
            };
            fixture.set_nested_helper_active(false);
            if let Some(error) = capture_error {
                support::retain_handoff_startup_failure(
                    &fixture.join("config"),
                    &error.to_string(),
                );
            }
            // The fixture guard reads its private producer journal and scans its
            // pre-registered import directories even when the success report is
            // missing/malformed, or the parent times out before parsing it.
            if let Err(error) = fixture.finish() {
                if thread::panicking() {
                    eprintln!("nested emergency cleanup unresolved: {error}");
                } else {
                    panic!("nested emergency cleanup unresolved: {error}");
                }
            }
            if fixture.terminated_servers() != 0 {
                if thread::panicking() {
                    eprintln!(
                        "nested parent recovered live servers; nested scenario remains failed"
                    );
                } else {
                    panic!(
                        "nested parent recovered live servers; emergency cleanup is a failed gate"
                    );
                }
            }
        }
    }
}

fn spawn_teardown_child(mode: &str, report: &Path) -> TeardownChild {
    let fixture = (mode != "term-resistant").then(unique_test_dir);
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["teardown_helper_process", "--exact", "--nocapture"])
        .env("HERDR_TEARDOWN_HELPER_MODE", mode)
        .env("HERDR_TEARDOWN_HELPER_REPORT", report);
    if let Some(fixture) = &fixture {
        fixture.set_nested_helper_active(true);
        command
            .env("HERDR_TEARDOWN_FIXTURE", fixture.as_ref())
            .env("HERDR_TEARDOWN_PARENT", std::process::id().to_string());
    }
    let child = TeardownChild(command.spawn().unwrap(), fixture);
    support::record_teardown_helper(child.0.id());
    child
}

#[test]
fn teardown_panic_subprocesses_leave_no_server() {
    let _lock = test_lock();
    for mode in [
        "panic-before-registration",
        "panic-before-readiness",
        "panic-after-handoff",
        "panic-before-response",
    ] {
        let base = unique_test_dir();
        let report = base.join("child-report.json");
        let mut child = spawn_teardown_child(mode, &report);
        let end = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < end, "nested {mode} exceeded deadline");
            thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(101), "nested panic must be observed");
        let records: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
        assert_eq!(
            records.len(),
            if matches!(mode, "panic-before-readiness" | "panic-before-registration") {
                1
            } else {
                2
            }
        );
        let mut leaked = Vec::new();
        for record in records {
            let pid = record["pid"].as_u64().unwrap() as u32;
            let birth = (
                record["birth"][0].as_u64().unwrap(),
                record["birth"][1].as_u64().unwrap(),
            );
            // Kernel birth lookup is independent of replacement discovery.
            if support::test_process_birth(pid).unwrap() == Some(birth) {
                leaked.push(pid);
                if let Some(identity) = support::test_process_identity(pid).unwrap() {
                    if identity.birth == birth {
                        support::terminate_test_process(
                            &identity,
                            Instant::now() + Duration::from_millis(2400),
                        )
                        .unwrap();
                    }
                }
            }
        }
        assert!(
            leaked.is_empty(),
            "nested {mode} leaked owned servers {leaked:?}; emergency cleanup is a failed gate"
        );
    }
}

#[test]
fn teardown_term_resistant_child_reaches_kill_and_is_reaped() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let report = base.join("ready");
    let mut child = spawn_teardown_child("term-resistant", &report);
    support::wait_for_file(&report, Duration::from_secs(5));
    let identity = support::test_process_identity(child.0.id())
        .unwrap()
        .unwrap();
    let started = Instant::now();
    support::terminate_test_process(&identity, started + Duration::from_millis(2400)).unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(400),
        "TERM should be ignored"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_ne!(
        support::test_process_birth(identity.pid).unwrap(),
        Some(identity.birth)
    );
    // The support helper reaps with waitpid; std Child may then report ECHILD.
    match child.0.try_wait() {
        Ok(Some(status)) => {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(libc::SIGKILL));
        }
        Err(error) => assert_eq!(error.raw_os_error(), Some(libc::ECHILD)),
        Ok(None) => panic!("controlled child still running"),
    }
}

#[test]
fn teardown_inspection_failure_retains_fixture_and_unwind_does_not_double_panic() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let path = base.to_path_buf();
    base.inject_inspection_failure(true);
    assert!(base.finish().unwrap_err().to_string().contains("injected"));
    assert!(
        path.exists(),
        "unresolved cleanup must retain fixture files"
    );
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _fixture = base;
        panic!("injected unwind with unresolved inspection");
    }));
    assert!(failed.is_err());
    assert!(path.exists());
    support::clear_handoff_inspection_failure(&path);
    cleanup_test_base(&path);
    assert!(!path.exists());
}

#[test]
fn teardown_fixture_root_preserves_short_paths_and_rejects_long_override() {
    let long = Path::new("/var/folders/b8/k03256lx2mzbvjm5dhy_kj4c0000gn/T");
    assert_eq!(fixture_root(long, None).unwrap(), Path::new("/tmp"));
    assert!(fixture_root(long, Some(long)).is_err());
    assert!(fixture_root(long, Some(Path::new("relative"))).is_err());
    assert_eq!(
        fixture_root(long, Some(Path::new("/tmp"))).unwrap(),
        Path::new("/tmp")
    );
}

#[test]
fn teardown_live_candidate_permission_failure_retains_fixture() {
    let _lock = test_lock();
    for error in [libc::EPERM, libc::EACCES] {
        let base = unique_test_dir();
        let helper_base = unique_test_dir();
        let report = helper_base.join("ready");
        let child = spawn_teardown_child("term-resistant", &report);
        support::wait_for_file(&report, Duration::from_secs(5));
        base.inject_executable_failure(child.0.id(), Some(error));
        let result = base.finish();
        let retained = base.exists();
        base.inject_executable_failure(child.0.id(), None);
        drop(child);
        assert!(
            result.is_err(),
            "live executable inspection error must fail cleanup"
        );
        assert!(retained, "incomplete inventory must retain fixture files");
        base.finish().unwrap();
    }
}

#[test]
fn teardown_parent_early_failures_clean_nested_producers_and_replacements() {
    let _lock = test_lock();
    for mode in [
        "hold-before-journal",
        "hold-before-readiness",
        "hold-after-handoff",
    ] {
        for failure in [
            "timeout",
            "missing-report",
            "malformed-report",
            "record-count",
        ] {
            let base = unique_test_dir();
            let report = base.join("child-report.json");
            let child = spawn_teardown_child(mode, &report);
            let fixture_path = child.1.as_ref().unwrap().to_path_buf();
            let end = Instant::now() + Duration::from_secs(12);
            let expected = if mode != "hold-after-handoff" { 1 } else { 2 };
            let records: Vec<serde_json::Value> = loop {
                if let Ok(bytes) = fs::read(&report) {
                    if let Ok(records) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) {
                        if records.len() == expected {
                            break records;
                        }
                    }
                }
                assert!(
                    Instant::now() < end,
                    "nested helper did not reach failure control point"
                );
                thread::sleep(Duration::from_millis(20));
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _owned_child = child;
                match failure {
                    "timeout" => panic!("injected parent deadline after helper control point"),
                    "missing-report" => {
                        fs::remove_file(&report).unwrap();
                        fs::read(&report).unwrap();
                    }
                    "malformed-report" => {
                        fs::write(&report, b"incomplete").unwrap();
                        serde_json::from_slice::<Vec<serde_json::Value>>(
                            &fs::read(&report).unwrap(),
                        )
                        .unwrap();
                    }
                    _ => assert_eq!(records.len(), 99, "injected unexpected record count"),
                }
            }));
            assert!(
                result.is_err(),
                "emergency recovery must remain a failed nested scenario"
            );
            assert!(
                !fixture_path.exists(),
                "parent guard did not finish its fixture"
            );
            for record in records {
                let pid = record["pid"].as_u64().unwrap() as u32;
                let birth = (
                    record["birth"][0].as_u64().unwrap(),
                    record["birth"][1].as_u64().unwrap(),
                );
                assert_ne!(
                    support::test_process_birth(pid).unwrap(),
                    Some(birth),
                    "nested server survived parent failure"
                );
            }
        }
    }
}

#[test]
fn teardown_incomplete_parent_journal_retains_ownership_and_cleans_known_servers() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config = base.join("config");
    let runtime = base.join("runtime");
    let socket = runtime.join("herdr.sock");
    let server = spawn_server(&config, &runtime, &socket);
    wait_for_socket(&socket, Duration::from_secs(10));
    assert_ok(request(
        &socket,
        serde_json::json!({"id":"journal:handoff","method":"server.live_handoff","params":{}}),
    ));
    let pid = wait_for_replacement_server_pid(
        &runtime,
        server.identity.as_ref().unwrap().pid,
        Duration::from_secs(5),
    );
    let replacement = support::test_process_identity(pid).unwrap().unwrap();
    let journal = base.join("producers.jsonl");
    let intact = fs::read(&journal).unwrap();
    for corrupt in [b"incomplete".as_slice(), b"".as_slice()] {
        if corrupt.is_empty() {
            fs::remove_file(&journal).unwrap();
        } else {
            fs::write(&journal, corrupt).unwrap();
        }
        assert!(base.finish().is_err());
        assert!(
            base.exists(),
            "incomplete ownership must retain fixture files"
        );
        assert_ne!(
            support::test_process_birth(pid).unwrap(),
            Some(replacement.birth),
            "known import was not cleaned despite journal failure"
        );
        fs::write(&journal, &intact).unwrap();
    }
    fs::write(base.join("pending-startup"), b"unrecorded child startup").unwrap();
    assert!(
        base.finish().is_err(),
        "unrecorded startup cannot be declared quiescent"
    );
    assert!(base.exists());
    fs::remove_file(base.join("pending-startup")).unwrap();
    drop(server);
    base.finish().unwrap();
}
