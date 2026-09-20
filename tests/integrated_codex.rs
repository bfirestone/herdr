//! The smoke harness's safety checks run without credentials or provider calls.
#![cfg(unix)]
use std::process::Command;

pub mod support;

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::{fs::PermissionsExt, net::UnixStream};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

type ProcessBirth = (u32, (u64, u64));

/// Every server has a fresh catalog and runtime. The provider below has no
/// credentials and no subprocesses; its control socket EOF ends it on panic.
struct ApiFixture {
    base: PathBuf,
    server: Child,
    socket: PathBuf,
    shells: std::cell::RefCell<Vec<ProcessBirth>>,
}

impl ApiFixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "c-{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        let config = base.as_path().join("config");
        let runtime = base.as_path().join("runtime");
        for dir in [
            config.join("herdr-dev"),
            config.join("herdr"),
            runtime.clone(),
        ] {
            std::fs::create_dir_all(dir).unwrap();
        }
        for name in ["herdr", "herdr-dev"] {
            std::fs::write(
                config.join(name).join("config.toml"),
                "onboarding = false\n",
            )
            .unwrap();
        }
        support::register_runtime_dir(&runtime);
        let socket = config.join("herdr-dev/sessions/q/herdr.sock");
        let server = Command::new(env!("CARGO_BIN_EXE_herdr"))
            .args(["--session", "q", "server"])
            .env_clear()
            .env("HOME", base.as_path())
            .env("XDG_CONFIG_HOME", config)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("TMPDIR", std::env::temp_dir())
            .env("HERDR_SOCKET_PATH", &socket)
            .env("HERDR_CLIENT_SOCKET_PATH", runtime.join("client.sock"))
            .env("SHELL", "/bin/sh")
            .env(
                "PATH",
                format!(
                    "{}:/opt/homebrew/bin:/usr/bin:/bin",
                    base.as_path().display()
                ),
            )
            .current_dir(base.as_path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let fixture = Self {
            base,
            server,
            socket,
            shells: Default::default(),
        };
        support::register_spawned_herdr_pid(Some(fixture.server.id()));
        support::wait_for_socket(&fixture.socket, Duration::from_secs(10));
        fixture
    }

    fn request(&self, method: &str, params: Value) -> Value {
        api_request(&self.socket, "fixture", method, params)
    }

    fn workspace(&self) -> Value {
        let created = self.request("workspace.create", json!({"cwd":self.base,"focus":true}))
            ["result"]
            .clone();
        let process = self.request(
            "pane.process_info",
            json!({"pane_id":created["root_pane"]["pane_id"]}),
        );
        let pid = process["result"]["process_info"]["shell_pid"]
            .as_u64()
            .unwrap() as u32;
        self.shells
            .borrow_mut()
            .push((pid, support::test_process_birth(pid).unwrap().unwrap()));
        created
    }

    fn launch(&self, workspace: &Value) -> (Value, ProviderFixture) {
        let path = self.base.join("control.sock");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let script = self.base.join("codex");
        std::fs::write(&script, SCRIPTED_CODEX).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let started = self.request(
            "agent.start_integrated",
            json!({"provider":"codex",
            "workspace_id":workspace["workspace"]["workspace_id"],"cwd":self.base}),
        );
        assert!(started.get("error").is_none(), "{started}");
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "scripted provider did not connect"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("provider listener: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut provider = ProviderFixture {
            control: BufReader::new(stream),
            processes: Vec::new(),
        };
        let hello = provider.event();
        for key in ["pid", "helper"] {
            let pid = hello[key].as_u64().unwrap() as u32;
            provider
                .processes
                .push((pid, support::test_process_birth(pid).unwrap().unwrap()));
        }
        assert_eq!(provider.event()["method"], "initialize");
        (started["result"].clone(), provider)
    }

    fn agent(&self, started: &Value) -> Value {
        self.request("agent.get", json!({"target":started["agent"]["pane_id"]}))["result"]["agent"]
            .clone()
    }

    fn wait_ready(&self, started: &Value, ready: bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let agent = self.agent(started);
            if agent["exact_prompt"]["ready"] == ready {
                return agent["exact_prompt"].clone();
            }
            assert!(
                Instant::now() < deadline,
                "recipient did not reach ready={ready}: {agent}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn assert_projection(&self, started: &Value, expected: &Value) {
        assert_eq!(&self.agent(started)["exact_prompt"], expected);
        for agents in [
            self.request("agent.list", json!({}))["result"]["agents"].clone(),
            self.request("session.snapshot", json!({}))["result"]["snapshot"]["agents"].clone(),
        ] {
            let agent = agents
                .as_array()
                .unwrap()
                .iter()
                .find(|agent| agent["terminal_id"] == started["agent"]["terminal_id"]);
            // A retired pane can already have disappeared from the snapshot.
            assert_eq!(
                agent
                    .map(|agent| &agent["exact_prompt"])
                    .unwrap_or(&Value::Null),
                expected
            );
        }
    }
}

struct ProviderFixture {
    control: BufReader<UnixStream>,
    processes: Vec<ProcessBirth>,
}

impl ProviderFixture {
    fn event(&mut self) -> Value {
        let mut line = String::new();
        self.control.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
    fn send(&mut self, frame: Value) {
        writeln!(self.control.get_mut(), "{frame}").unwrap();
    }
    fn initialize(&mut self, cwd: &Value) {
        self.send(json!({"id":"initialize","result":{"userAgent":"codex/0.154.0"}}));
        assert_eq!(self.event()["method"], "initialized");
        assert_eq!(self.event()["method"], "thread/start");
        self.send(
            json!({"id":"thread","result":{"thread":{"id":"fixed-thread"},
            "cwd":cwd,"approvalPolicy":"on-request","sandbox":{"type":"workspaceWrite"}}}),
        );
    }
}

impl Drop for ProviderFixture {
    fn drop(&mut self) {
        let _ = self.control.get_mut().shutdown(std::net::Shutdown::Both);
        // EOF ends the script; the helper must reap it and exit. Inspect exact
        // birth identities only; never signal a PID or leave a rescue as PASS.
        let gone = support::wait_until(Duration::from_secs(5), Duration::from_millis(20), || {
            self.processes
                .iter()
                .all(|(pid, birth)| support::test_process_birth(*pid).unwrap() != Some(*birth))
        });
        assert!(gone, "owned provider/helper did not exit");
    }
}

// No real provider, auth, tools, or child processes. Forwarded frames stay in
// memory on an observer socket, never in argv/environment/files. select drains
// both sources and exits on either EOF, including when a test assertion fails.
const SCRIPTED_CODEX: &str = r#"#!/usr/bin/env python3
import json, os, select, socket, sys, time
s=socket.socket(socket.AF_UNIX)
s.connect(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'control.sock'))
s.sendall((json.dumps({'pid':os.getpid(),'helper':os.getppid()})+'\n').encode())
buffers={0:b'',s.fileno():b''}
deadline=time.monotonic()+45
while time.monotonic()<deadline:
    for fd in select.select(list(buffers),[],[],0.1)[0]:
        data=os.read(fd,65536)
        if not data: sys.exit(0)
        buffers[fd]+=data
        if len(buffers[fd])>524288: sys.exit(2)
        while b'\n' in buffers[fd]:
            line,buffers[fd]=buffers[fd].split(b'\n',1)
            frame=json.loads(line)
            if fd==0: s.sendall(line+b'\n')
            elif frame.get('fixture')=='barrier': s.sendall(b'{"barrier":true}\n')
            else: sys.stdout.buffer.write(line+b'\n'); sys.stdout.buffer.flush()
sys.exit(3)
"#;

fn exact_params(started: &Value, text: &str) -> Value {
    json!({"terminal_id":started["agent"]["terminal_id"],"server_instance":started["server_instance"],
        "recipient_token":started["recipient_token"],"text":text})
}

#[test]
fn public_codex_capability_tracks_handshake_admission_and_replacement() {
    let fixture = ApiFixture::new();
    let workspace = fixture.workspace();
    let ordinary_pane = &workspace["root_pane"]["pane_id"];
    for agent in ["codex", "claude"] {
        let reply = fixture.request(
            "pane.report_agent",
            json!({"pane_id":ordinary_pane,
            "source":"custom:fixture","agent":agent,"state":"idle"}),
        );
        assert!(reply.get("error").is_none(), "{reply}");
        let ordinary = fixture.request("agent.get", json!({"target":ordinary_pane}));
        assert!(ordinary["result"]["agent"].is_object(), "{ordinary}");
        assert!(ordinary["result"]["agent"]["exact_prompt"].is_null());
    }
    assert_eq!(
        fixture.request(
            "agent.start_integrated",
            json!({"provider":"claude",
        "workspace_id":workspace["workspace"]["workspace_id"],"cwd":fixture.base})
        )["error"]["code"],
        "integrated_start_failed"
    );
    let (started, mut provider) = fixture.launch(&workspace);
    fixture.assert_projection(&started, &Value::Null);
    provider.send(json!({"id":"initialize","result":{"userAgent":"codex/0.154.0"}}));
    assert_eq!(provider.event()["method"], "initialized");
    assert_eq!(provider.event()["method"], "thread/start");
    fixture.assert_projection(&started, &Value::Null);
    provider.send(
        json!({"id":"thread","result":{"thread":{"id":"fixed-thread"},
        "cwd":fixture.base,"approvalPolicy":"on-request","sandbox":{"type":"workspaceWrite"}}}),
    );
    let capability = fixture.wait_ready(&started, true);
    assert_eq!(
        capability,
        json!({"version":1,"server_instance":started["server_instance"],
        "recipient_token":started["recipient_token"],"transport":"recipient_channel_v1","ready":true})
    );
    fixture.assert_projection(&started, &capability);

    // Check the advertised UTF-8 boundary through the real admission path.
    let oversized = "é".repeat(32769);
    assert_eq!(
        fixture.request("agent.prompt_exact", exact_params(&started, &oversized))["result"]["code"],
        "invalid_text"
    );
    let text = format!("  Unicode é and embedded\nnewline {}  ", "x".repeat(65500));
    assert_eq!(text.len(), 65536);
    let socket = fixture.socket.clone();
    let params = exact_params(&started, &text);
    let submit = std::thread::spawn(move || {
        api_request(&socket, "exact-request", "agent.prompt_exact", params)
    });
    let frame = provider.event();
    assert_eq!(frame["method"], "turn/start");
    assert_eq!(frame["params"]["threadId"], "fixed-thread");
    assert_eq!(frame["params"]["input"][0]["text"], text);
    let mut busy = capability.clone();
    busy["ready"] = false.into();
    fixture.wait_ready(&started, false);
    fixture.assert_projection(&started, &busy);
    assert_eq!(
        fixture.request("agent.prompt_exact", exact_params(&started, "busy"))["result"]["code"],
        "queue_full"
    );
    provider.send(json!({"id":frame["id"],"result":{"turn":{"id":"turn-one"}}}));
    let result = submit.join().unwrap()["result"].clone();
    assert_eq!(result["type"], "agent_prompt_exact_result");
    for key in ["server_instance", "recipient_token"] {
        assert_eq!(result[key], started[key]);
    }
    assert_eq!(result["terminal_id"], started["agent"]["terminal_id"]);
    assert_eq!(result["outcome"], "accepted");
    assert_eq!(result["acceptance"], "provider_input_accepted");
    assert_eq!(result["submission_id"], "turn-one");
    fixture.assert_projection(&started, &busy);
    provider.send(json!({"id":"approval","method":"item/commandExecution/requestApproval",
        "params":{"threadId":"fixed-thread","turnId":"turn-one","itemId":"cmd","startedAtMs":1, "command":"true","cwd":fixture.base}}));
    let deadline = Instant::now() + Duration::from_secs(5);
    while fixture.agent(&started)["agent_status"] != "blocked" {
        assert!(Instant::now() < deadline, "pending consent not projected");
        std::thread::sleep(Duration::from_millis(10));
    }
    fixture.assert_projection(&started, &busy);
    provider.send(json!({"method":"serverRequest/resolved","params":{"requestId":"approval"}}));
    provider.send(json!({"method":"turn/completed","params":{"threadId":"fixed-thread","turn":{"id":"turn-one"}}}));
    assert_eq!(fixture.wait_ready(&started, true), capability);
    fixture.assert_projection(&started, &capability);
    provider.send(json!({"method":"thread/reset","params":{"threadId":"fixed-thread"}}));
    drop(provider);
    fixture.assert_projection(&started, &Value::Null);
    let (replacement, mut provider) = fixture.launch(&workspace);
    provider.initialize(&json!(fixture.base));
    fixture.wait_ready(&replacement, true);
    assert_ne!(replacement["recipient_token"], started["recipient_token"]);
    let mut stale = exact_params(&started, "must not reach replacement");
    stale["terminal_id"] = replacement["agent"]["terminal_id"].clone();
    assert_eq!(
        fixture.request("agent.prompt_exact", stale)["result"]["code"],
        "stale_recipient"
    );
    provider.send(json!({"fixture":"barrier"}));
    assert_eq!(
        provider.event(),
        json!({"barrier":true}),
        "stale body reached replacement pipe"
    );
}

#[test]
fn public_codex_capability_rejects_unqualified_handshakes_without_prompt_writes() {
    let fixture = ApiFixture::new();
    let workspace = fixture.workspace();
    for case in [
        "version",
        "missing-version",
        "initialize-id",
        "thread-id",
        "cwd",
        "malformed",
    ] {
        let (started, mut provider) = fixture.launch(&workspace);
        fixture.assert_projection(&started, &Value::Null);
        assert_eq!(
            fixture.request("agent.prompt_exact", exact_params(&started, "early"))["result"]
                ["code"],
            "not_ready"
        );
        let mut initialize = json!({"id":"initialize","result":{"userAgent":"codex/0.154.0"}});
        match case {
            "version" => initialize["result"]["userAgent"] = "codex/0.155.0".into(),
            "missing-version" => initialize["result"] = json!({}),
            "initialize-id" => initialize["id"] = "different".into(),
            _ => {}
        }
        provider.send(initialize);
        if matches!(case, "thread-id" | "cwd" | "malformed") {
            assert_eq!(provider.event()["method"], "initialized");
            assert_eq!(provider.event()["method"], "thread/start");
            let mut thread = json!({"id":"thread","result":{"thread":{"id":"fixed-thread"},
                "cwd":fixture.base,"approvalPolicy":"on-request","sandbox":{}}});
            match case {
                "thread-id" => thread["id"] = "different".into(),
                "cwd" => thread["result"]["cwd"] = "/wrong-workspace".into(),
                _ => thread["result"]["thread"] = json!({"id":""}),
            }
            provider.send(thread);
        }
        let mut remaining = String::new();
        std::io::Read::read_to_string(&mut provider.control, &mut remaining).unwrap();
        assert!(
            remaining.is_empty(),
            "unqualified provider received further frames"
        );
        drop(provider);
        fixture.assert_projection(&started, &Value::Null);
        assert_eq!(
            fixture.request("agent.prompt_exact", exact_params(&started, "late"))["result"]["code"],
            "revoked_before_write"
        );
    }
}

fn api_request(socket: &std::path::Path, id: &str, method: &str, params: Value) -> Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    writeln!(
        stream,
        "{}",
        json!({"id":id,"method":method,"params":params})
    )
    .unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["id"], id);
    response
}

impl Drop for ApiFixture {
    fn drop(&mut self) {
        let panicking = std::thread::panicking();
        if !panicking {
            // Graceful server shutdown owns pane and helper teardown.
            self.request("server.stop", json!({}));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let exited = loop {
            match self.server.try_wait() {
                Ok(Some(_)) => break true,
                Err(error) if panicking && error.raw_os_error() == Some(libc::ECHILD) => {
                    break true
                }
                Err(error) => panic!("fixture server wait: {error}"),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Ok(None) => break false,
            }
        };
        if !exited {
            self.server.kill().unwrap();
            self.server.wait().unwrap();
        }
        support::unregister_spawned_herdr_pid(Some(self.server.id()));
        assert!(exited, "fixture server required emergency termination");
        assert!(
            support::wait_until(Duration::from_secs(5), Duration::from_millis(20), || {
                self.shells
                    .borrow()
                    .iter()
                    .all(|(pid, birth)| support::test_process_birth(*pid).unwrap() != Some(*birth))
            }),
            "fixture workspace shell survived server shutdown"
        );
        support::unregister_runtime_dir(&self.base.join("runtime"));
        if !panicking {
            std::fs::remove_dir_all(&self.base).unwrap();
        }
    }
}

#[test]
fn public_codex_capability_ping_is_versioned_and_bounded() {
    let fixture = ApiFixture::new();
    assert_eq!(
        fixture.request("ping", json!({}))["result"]["capabilities"]["agent_prompt_exact"],
        json!({"version":1,"max_text_bytes":65536,"guarantee":"recipient_instance_v1"})
    );
    assert!(
        fixture.request("session.snapshot", json!({}))["result"]["snapshot"]["agents"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn codex_qualification_harness_has_offline_safety_contracts() {
    let output = Command::new("python3")
        .args([
            "-m",
            "unittest",
            "scripts.test_integrated_codex",
            "scripts.test_ci_codex_sandbox",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("python3 is required for integrated provider fixtures");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("Ran "));
}

#[test]
fn codex_smoke_help_is_offline_and_documents_explicit_targets() {
    let output = Command::new("python3")
        .args(["scripts/test_integrated_codex.py", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    for option in [
        "--session",
        "--scratch",
        "--provider-path",
        "--herdr-bin",
        "--provider-fixtures-only",
    ] {
        assert!(help.contains(option), "missing {option}");
    }
}

#[test]
fn codex_ci_covers_both_bootstrap_platforms_without_live_authentication() {
    let workflow = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/integrated-agents.yml"
    ))
    .expect("a dedicated integrated-agent fixture workflow is required");
    for required in [
        "ubuntu-24.04",
        "macos-latest",
        "1.98.1",
        "--provider-fixtures-only",
        "just ci",
        "just docs-contract-test",
    ] {
        assert!(
            workflow.contains(required),
            "missing CI coverage: {required}"
        );
    }
    assert!(
        !workflow.contains("secrets."),
        "provider fixture CI must not require authentication secrets"
    );
}
