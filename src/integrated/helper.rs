use super::{
    channel::{read_frame, write_frame, CONTROL_LIMIT, INPUT_LIMIT},
    codex::{Codex, Effect, SubmissionOrigin},
    identity::RecipientIdentity,
    render::{self, Input, View},
};
use serde_json::json;
use std::{
    io::{self, BufReader, Read, Write},
    path::Path,
    process::{Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};

enum Protocol {
    Codex(Codex),
    Claude(super::claude::Claude),
}
impl Protocol {
    fn state(&self) -> super::OwnerState {
        match self {
            Self::Codex(p) => p.state,
            Self::Claude(p) => p.state,
        }
    }
    fn initialize(&self) -> serde_json::Value {
        match self {
            Self::Codex(_) => Codex::initialize(),
            Self::Claude(_) => super::claude::Claude::initialize(),
        }
    }
    fn submit(&mut self, origin: SubmissionOrigin, text: String) -> Vec<Effect> {
        match self {
            Self::Codex(p) => p.submit(origin, text),
            Self::Claude(p) => p.submit(origin, text),
        }
    }
    fn event(&mut self, frame: serde_json::Value) -> Result<Vec<Effect>, ()> {
        match self {
            Self::Codex(p) => p.event(frame),
            Self::Claude(p) => p.event(frame),
        }
    }
    fn decision(&mut self, id: &serde_json::Value, decision: &str) -> Result<Vec<Effect>, ()> {
        match self {
            Self::Codex(p) => Ok(p.decision(id, decision)),
            Self::Claude(p) => {
                let effects = p.decision(id, decision);
                if p.state == super::OwnerState::Revoked {
                    return Err(());
                }
                Ok(effects)
            }
        }
    }
    fn cards(&self) -> Vec<super::approvals::Card> {
        match self {
            Self::Codex(p) => p.approvals.cards(),
            Self::Claude(p) => p.cards(),
        }
    }
    fn name(&self) -> &str {
        match self {
            Self::Codex(_) => "Codex",
            Self::Claude(_) => "Claude",
        }
    }
}

pub(crate) fn run(args: &[String]) -> io::Result<()> {
    let [path, nonce, cwd, provider] = args else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    let provider = super::ProviderKind::parse(provider).ok_or(io::ErrorKind::InvalidInput)?;
    let (command, protocol) = match provider {
        super::ProviderKind::Codex => {
            let mut command = Command::new("codex");
            command.args(["app-server", "--listen", "stdio://"]);
            (command, Protocol::Codex(Codex::new(cwd.clone())))
        }
        super::ProviderKind::Claude => {
            let session = super::claude::fresh_uuid()?;
            (
                super::claude::Claude::command(&session),
                Protocol::Claude(super::claude::Claude::new(cwd.clone(), session)),
            )
        }
    };
    run_protocol(
        &[path.clone(), nonce.clone(), cwd.clone()],
        command,
        protocol,
        true,
        #[cfg(test)]
        None,
        #[cfg(test)]
        None,
    )
}

#[cfg(test)]
fn run_provider(
    args: &[String],
    command: Command,
    render_enabled: bool,
    cleanup_gate: Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>,
) -> io::Result<()> {
    run_protocol(
        args,
        command,
        Protocol::Codex(Codex::new(args[2].clone())),
        render_enabled,
        cleanup_gate,
        None,
    )
}

fn run_protocol(
    args: &[String],
    mut command: Command,
    mut protocol: Protocol,
    render_enabled: bool,
    #[cfg(test)] cleanup_gate: Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>,
    #[cfg(test)] test_ui: Option<mpsc::Receiver<Input>>,
) -> io::Result<()> {
    let [path, nonce, cwd] = args else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    let mut control = crate::platform::connect_recipient(Path::new(path))?;
    writeln!(control, "{nonce}")?;
    let mut reader = BufReader::new(control.try_clone()?);
    let identity: RecipientIdentity =
        serde_json::from_value(read_frame(&mut reader, CONTROL_LIMIT)?)
            .map_err(io::Error::other)?;
    command
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in [
        "HERDR_SOCKET_PATH",
        "HERDR_CLIENT_SOCKET_PATH",
        "HERDR_SESSION",
        "HERDR_PANE_ID",
    ] {
        command.env_remove(name);
    }
    crate::platform::configure_recipient_provider(&mut command)?;
    let mut child = command.spawn()?;
    let mut readers = Vec::new();
    let result = (|| -> io::Result<()> {
        let mut input = crate::platform::RecipientProviderInput(child.stdin.take().unwrap());
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (provider_tx, provider_rx) = mpsc::sync_channel(4);
        readers.push(std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let result = read_frame(&mut reader, CONTROL_LIMIT);
                let failed = result.is_err();
                if provider_tx.send(result).is_err() || failed {
                    break;
                }
            }
        }));
        let (control_tx, control_rx) = mpsc::sync_channel(1);
        readers.push(std::thread::spawn(move || loop {
            let result = read_frame(&mut reader, INPUT_LIMIT);
            let failed = result.is_err();
            if control_tx.send(result).is_err() || failed {
                break;
            }
        }));
        let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
        readers.push(std::thread::spawn(move || {
            // Retain no stderr bodies; bound total bytes and fail closed on flood.
            let mut stderr = stderr;
            let mut count = 0;
            let mut buffer = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                count += n;
                if count > 65536 {
                    let _ = stderr_tx.send(());
                    break;
                }
            }
        }));
        let view = Arc::new(Mutex::new(View::default()));
        let (ui_tx, ui_rx) = mpsc::sync_channel(1);
        if render_enabled {
            render::start(view.clone(), ui_tx.clone());
        }
        #[cfg(test)]
        let ui_rx = test_ui.unwrap_or(ui_rx);
        write_frame(&mut input, &protocol.initialize(), INPUT_LIMIT)?;
        let startup = Instant::now();
        let mut pending_since = None;
        let mut local_sequence = 0u64;
        let mut effects = Vec::new();
        let session = (|| -> io::Result<()> {
            loop {
                if stderr_rx.try_recv().is_ok() {
                    return Err(io::Error::other("provider stderr overflow"));
                }
                if crate::platform::recipient_provider_exited(&child)? {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                if protocol.state() == super::owner::OwnerState::Starting
                    && startup.elapsed() > Duration::from_secs(15)
                    || pending_since
                        .is_some_and(|time: Instant| time.elapsed() > Duration::from_secs(15))
                {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                match control_rx.try_recv() {
                    Ok(frame) => {
                        let frame = frame?;
                        let supplied: RecipientIdentity =
                            serde_json::from_value(frame["identity"].clone())
                                .map_err(io::Error::other)?;
                        if supplied != identity || frame["kind"] != "submit" {
                            return Err(io::ErrorKind::InvalidData.into());
                        }
                        let id = frame["id"]
                            .as_str()
                            .ok_or(io::ErrorKind::InvalidData)?
                            .to_owned();
                        let text = frame["text"]
                            .as_str()
                            .ok_or(io::ErrorKind::InvalidData)?
                            .to_owned();
                        effects.extend(protocol.submit(SubmissionOrigin::Remote(id), text));
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        return Err(io::ErrorKind::UnexpectedEof.into())
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
                // Provider notifications precede UI decisions, invalidating resolved cards first.
                for _ in 0..16 {
                    match provider_rx.try_recv() {
                        Ok(frame) => effects.extend(
                            protocol
                                .event(frame?)
                                .map_err(|_| io::ErrorKind::InvalidData)?,
                        ),
                        Err(mpsc::TryRecvError::Disconnected) => {
                            return Err(io::ErrorKind::UnexpectedEof.into())
                        }
                        Err(mpsc::TryRecvError::Empty) => break,
                    }
                }
                if let Ok(event) = ui_rx.try_recv() {
                    match event {
                        Input::Close => return Ok(()),
                        Input::Text(text) => {
                            local_sequence += 1;
                            effects.extend(
                                protocol.submit(SubmissionOrigin::Local(local_sequence), text),
                            );
                        }
                        Input::Decision(id, decision) => effects.extend(
                            protocol
                                .decision(&id, &decision)
                                .map_err(|_| io::ErrorKind::InvalidData)?,
                        ),
                    }
                }
                for effect in effects.drain(..) {
                    match effect {
                        Effect::Write(frame) => {
                            if frame["method"] == "turn/start" || frame["type"] == "user" {
                                pending_since = Some(Instant::now());
                            }
                            write_frame(&mut input, &frame, INPUT_LIMIT)?;
                        }
                        Effect::Result(id, outcome) => {
                            if matches!(
                                outcome,
                                super::owner::SubmissionOutcome::Accepted { .. }
                                    | super::owner::SubmissionOutcome::Unknown
                            ) {
                                pending_since = None;
                            }
                            if let SubmissionOrigin::Remote(id) = id {
                                write_frame(
                                    &mut control,
                                    &json!({"kind":"result","identity":identity,"id":id,"result":outcome}),
                                    CONTROL_LIMIT,
                                )?;
                            } else {
                                view.lock()
                                    .unwrap()
                                    .text(&format!("\nLocal submission: {outcome:?}\n"));
                            }
                        }
                        Effect::Text(text) => view.lock().unwrap().text(&text),
                        Effect::State(state) => {
                            view.lock().unwrap().status =
                                format!("{} integrated — {state:?}", protocol.name());
                            write_frame(
                                &mut control,
                                &json!({"kind":"state","identity":identity,"state":state}),
                                CONTROL_LIMIT,
                            )?;
                        }
                    }
                }
                view.lock().unwrap().cards = protocol.cards();
                std::thread::sleep(Duration::from_millis(5));
            }
        })();
        {
            let mut view = view.lock().unwrap();
            if session.is_err() {
                view.text("\nProvider protocol failed or unsupported interaction; recipient retired. Pending input may have been delivered. Inspect before resending.\n");
            }
            view.ended = true;
            view.status = "Recipient revoked; never replay pending input".into();
        }
        let _ = control.shutdown(std::net::Shutdown::Both);
        session
    })();
    let _ = control.shutdown(std::net::Shutdown::Both);
    #[cfg(test)]
    let cleanup_gate_result = cleanup_gate.map(|(arrived, release)| {
        // A fixture assertion can drop either peer; still reap the owned provider.
        arrived.send(()).map_err(io::Error::other)?;
        release
            .recv_timeout(Duration::from_secs(5))
            .map_err(io::Error::other)
    });
    crate::platform::terminate_recipient_provider(&mut child);
    let reader_deadline = Instant::now() + Duration::from_secs(2);
    for reader in readers {
        while !reader.is_finished() && Instant::now() < reader_deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        if !reader.is_finished() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned provider pipe did not close",
            ));
        }
        let _ = reader.join();
    }
    #[cfg(test)]
    if let Some(gate_result) = cleanup_gate_result {
        gate_result?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrated::{Owner, OwnerState, SubmissionOutcome};
    const PROVIDER: &str = r#"
import json,sys,os,subprocess,socket,select
# A descendant deliberately retains the provider pipes until owned group cleanup.
descendant=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"])
observer=socket.create_connection(('127.0.0.1',int(os.environ['HERDR_FIXTURE_OBSERVER'])))
sync=observer.makefile('rwb',buffering=0)
def observe(value): sync.write((value+'\n').encode())
def await_release(): assert sync.readline()==b'continue\n'
observe(str(descendant.pid))
read=lambda:json.loads(sys.stdin.readline())
def send(x): print(json.dumps(x),flush=True)
a=read();send({'id':a['id'],'result':{'userAgent':'codex/0.154.0'}})
assert read()['method']=='initialized'
a=read();send({'id':a['id'],'result':{'thread':{'id':'fixed'},'cwd':os.getcwd(),'approvalPolicy':'on-request','sandbox':{'type':'readOnly'}}})
mode=os.environ['HERDR_FIXTURE_MODE']
if mode in ['queued','queued-reset','replacement']:
 observe('holding-input')
 await_release()
 if mode in ['queued','queued-reset']:
  assert select.select([sys.stdin],[],[],5)[0], 'provider input was not buffered'
  observe('input-buffered')
 if mode=='queued': await_release()
 if mode=='queued-reset':
  send({'method':'thread/reset','params':{'threadId':'fixed'}})
  observe('reset-sent')
  await_release()
 if mode=='replacement':
  assert not select.select([sys.stdin],[],[],0)[0], 'replacement received old bytes'
  observe('empty-input')
  await_release()
a=read();assert a['method']=='turn/start';assert a['params']['threadId']=='fixed'
text=a['params']['input'][0]['text']
assert text not in str(sys.argv) and text not in str(dict(os.environ))
assert os.listdir('.')==[]
mode=os.environ['HERDR_FIXTURE_MODE']
observe('received:1')
if mode in ['busy','late']: await_release()
if mode in ['late','queued','queued-reset']:
 send({'id':a['id'],'result':{'turn':{'id':'late-turn'}}})
 observe('late-sent')
 sys.stdin.read()
 sys.exit(0)
if mode=='wrong': send({'method':'item/agentMessage/delta','params':{'threadId':'replacement','delta':'wrong'}})
elif mode=='reset':send({'method':'thread/reset','params':{'threadId':'fixed'}})
elif mode=='overflow':
 # The bounded reader can close between print's text and newline writes.
 # Keep provider exit from overtaking the queued invalid-frame error.
 try: print('x'*1048577,flush=True)
 except BrokenPipeError: pass
else:
 if mode=='replacement': assert text=='new-instance-body'
 send({'id':a['id'],'result':{'turn':{'id':'accepted-turn'}}})
 if mode=='busy': await_release()
 send({'method':'turn/completed','params':{'threadId':'fixed','turn':{'id':'accepted-turn'}}})
 # With no renderer/client attached, the process remains alive to admit a second input.
 a=read();assert a['method']=='turn/start'
 observe('received:2')
 send({'id':a['id'],'result':{'turn':{'id':'second-turn'}}})
 # Wait for owned cleanup rather than racing the acknowledgment with process exit.
 sys.stdin.read()
# Keep EOF from racing the specific protocol violation being tested.
if mode in ["wrong", "reset", "overflow"]: sys.stdin.read()
"#;
    #[test]
    fn fake_provider_process_has_private_body_and_survives_absent_renderer() {
        fixture("accept");
    }
    #[test]
    fn fake_provider_wrong_thread_reset_and_overflow_retire_without_replay() {
        for mode in ["wrong", "reset", "overflow"] {
            fixture(mode);
        }
    }
    #[test]
    fn fake_provider_pending_and_active_turn_admission_forwards_only_one_input() {
        fixture("busy");
    }
    #[test]
    fn fake_provider_late_ack_after_retirement_cannot_revive_owner() {
        fixture("late");
    }
    #[test]
    fn fake_provider_queued_input_stays_with_retired_process_across_replacement() {
        fixture("queued");
    }
    #[test]
    fn fake_provider_buffered_input_reset_stays_with_retired_process() {
        fixture("queued-reset");
    }
    #[test]
    fn fake_provider_disconnected_cleanup_barrier_still_reaps_descendant() {
        fixture("cleanup-disconnected");
    }
    fn replacement_while_old_input_held(old: &mut BufReader<std::net::TcpStream>) {
        use std::io::BufRead;
        fn observed(reader: &mut BufReader<std::net::TcpStream>) -> String {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            line.trim_end().to_owned()
        }
        let bootstrap = crate::platform::RecipientBootstrap::new().unwrap();
        let directory = std::env::temp_dir().join(format!(
            "herdr-replacement-{}",
            crate::platform::recipient_random().unwrap()
        ));
        std::fs::create_dir(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        let args = vec![
            bootstrap.path().to_string_lossy().into_owned(),
            bootstrap.nonce.clone(),
            directory.to_string_lossy().into_owned(),
        ];
        let owner = Owner::launch_codex(
            RecipientIdentity {
                server_instance: "test-server".into(),
                recipient_token: "replacement-recipient".into(),
                terminal_id: "test-terminal".into(),
            },
            bootstrap,
            std::process::id(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut provider = Command::new("python3");
        provider
            .args(["-u", "-c", PROVIDER])
            .env("HERDR_FIXTURE_MODE", "replacement")
            .env(
                "HERDR_FIXTURE_OBSERVER",
                listener.local_addr().unwrap().port().to_string(),
            );
        let helper = std::thread::spawn(move || run_provider(&args, provider, false, None));
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut observer = BufReader::new(stream);
        let _descendant: u32 = observed(&mut observer).parse().unwrap();
        owner.wait_for_phase(OwnerState::Idle);
        assert_eq!(observed(&mut observer), "holding-input");
        // Release A only after the replacement has its own initialized process.
        old.get_mut().write_all(b"continue\n").unwrap();
        assert_eq!(observed(old), "received:1");
        assert_eq!(observed(old), "late-sent");
        observer.get_mut().write_all(b"continue\n").unwrap();
        assert_eq!(observed(&mut observer), "empty-input");
        assert_eq!(owner.state(), OwnerState::Idle);
        // A separate B proves that the replacement pipe is live, not a dead sink.
        let pending = owner
            .reserve(&owner.identity, "new-request", "new-instance-body")
            .unwrap();
        owner.forward("new-request", "new-instance-body");
        observer.get_mut().write_all(b"continue\n").unwrap();
        assert_eq!(observed(&mut observer), "received:1");
        assert!(matches!(
            owner.wait(pending),
            SubmissionOutcome::Accepted { .. }
        ));
        // Acceptance precedes turn completion. Observe its final control write
        // before closing the stream, so shutdown cannot race that Idle frame.
        owner.wait_for_phase(OwnerState::Idle);
        owner.revoke();
        assert_eq!(
            helper.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        std::fs::remove_dir(directory).unwrap();
    }
    fn fixture(mode: &str) {
        let Ok(bootstrap) = crate::platform::RecipientBootstrap::new() else {
            return;
        };
        let directory = std::env::temp_dir().join(format!(
            "herdr-provider-fixture-{}",
            crate::platform::recipient_random().unwrap()
        ));
        std::fs::create_dir(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        let args = vec![
            bootstrap.path().to_string_lossy().into_owned(),
            bootstrap.nonce.clone(),
            directory.to_string_lossy().into_owned(),
        ];
        let owner = Owner::launch_codex(
            RecipientIdentity {
                server_instance: "test-server".into(),
                recipient_token: "test-recipient".into(),
                terminal_id: "test-terminal".into(),
            },
            bootstrap,
            std::process::id(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut provider = Command::new("python3");
        provider
            .args(["-u", "-c", PROVIDER])
            .env(
                "HERDR_FIXTURE_MODE",
                if mode == "cleanup-disconnected" {
                    "late"
                } else {
                    mode
                },
            )
            .env(
                "HERDR_FIXTURE_OBSERVER",
                listener.local_addr().unwrap().port().to_string(),
            );
        let (arrived_tx, arrived_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let gate = matches!(
            mode,
            "late" | "queued" | "queued-reset" | "cleanup-disconnected"
        )
        .then_some((arrived_tx, release_rx));
        let helper = std::thread::spawn(move || run_provider(&args, provider, false, gate));
        let (observer, _) = listener.accept().unwrap();
        observer
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut observer = BufReader::new(observer);
        let receive = |reader: &mut BufReader<std::net::TcpStream>| {
            use std::io::BufRead;
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            line.trim_end().to_owned()
        };
        let descendant: u32 = receive(&mut observer).parse().unwrap();
        owner.wait_for_phase(OwnerState::Idle);
        let prompt = "private-fixture-body-79c6\nquote ' \" end";
        let result = owner.reserve(&owner.identity, "request1", prompt).unwrap();
        owner.forward("request1", prompt);
        if matches!(mode, "queued" | "queued-reset") {
            assert_eq!(receive(&mut observer), "holding-input");
            observer.get_mut().write_all(b"continue\n").unwrap();
            assert_eq!(receive(&mut observer), "input-buffered");
            if mode == "queued-reset" {
                assert_eq!(receive(&mut observer), "reset-sent");
            } else {
                owner.revoke();
            }
            assert_eq!(owner.wait(result), SubmissionOutcome::Unknown);
            // The production loop has stopped but the old provider is kept alive
            // by the existing test-only cleanup barrier, with A still unread.
            arrived_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            replacement_while_old_input_held(&mut observer);
            assert_eq!(owner.state(), OwnerState::Revoked);
            assert_eq!(
                owner
                    .reserve(&owner.identity, "retired", prompt)
                    .unwrap_err(),
                SubmissionOutcome::rejected("revoked_before_write")
            );
            release_tx.send(()).unwrap();
        } else if mode == "cleanup-disconnected" {
            assert_eq!(receive(&mut observer), "received:1");
            owner.revoke();
            assert_eq!(owner.wait(result), SubmissionOutcome::Unknown);
            arrived_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            // Model assertion unwinding after arrival: the release sender drops.
            // The helper must report that error only after owned cleanup.
            drop(release_tx);
        } else if mode == "late" {
            assert_eq!(receive(&mut observer), "received:1");
            owner.revoke();
            assert_eq!(owner.wait(result), SubmissionOutcome::Unknown);
            arrived_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            observer.get_mut().write_all(b"continue\n").unwrap();
            assert_eq!(receive(&mut observer), "late-sent");
            assert_eq!(owner.state(), OwnerState::Revoked);
            assert_eq!(
                owner
                    .reserve(&owner.identity, "late-retry", prompt)
                    .unwrap_err(),
                SubmissionOutcome::rejected("revoked_before_write")
            );
            release_tx.send(()).unwrap();
        } else if mode == "accept" || mode == "busy" {
            assert_eq!(receive(&mut observer), "received:1");
            if mode == "busy" {
                assert_eq!(
                    owner
                        .reserve(&owner.identity, "pending-duplicate", prompt)
                        .unwrap_err(),
                    SubmissionOutcome::rejected("queue_full")
                );
                observer.get_mut().write_all(b"continue\n").unwrap();
            }
            assert!(matches!(
                owner.wait(result),
                SubmissionOutcome::Accepted { .. }
            ));
            if mode == "busy" {
                assert_eq!(
                    owner
                        .reserve(&owner.identity, "active-duplicate", prompt)
                        .unwrap_err(),
                    SubmissionOutcome::rejected("not_ready")
                );
                observer.get_mut().write_all(b"continue\n").unwrap();
            }
            owner.wait_for_phase(OwnerState::Idle);
            let result = owner.reserve(&owner.identity, "request2", prompt).unwrap();
            owner.forward("request2", prompt);
            assert_eq!(receive(&mut observer), "received:2");
            assert!(matches!(
                owner.wait(result),
                SubmissionOutcome::Accepted { .. }
            ));
            owner.revoke();
        } else {
            assert_eq!(receive(&mut observer), "received:1");
            assert_eq!(owner.wait(result), SubmissionOutcome::Unknown);
        }
        let termination = helper.join().unwrap().unwrap_err();
        let expected = if mode == "cleanup-disconnected" {
            assert_eq!(
                termination
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<mpsc::RecvTimeoutError>()),
                Some(&mpsc::RecvTimeoutError::Disconnected)
            );
            io::ErrorKind::Other
        } else if matches!(mode, "wrong" | "reset" | "overflow" | "queued-reset") {
            io::ErrorKind::InvalidData
        } else {
            io::ErrorKind::UnexpectedEof
        };
        assert_eq!(
            termination.kind(),
            expected,
            "unexpected helper termination in {mode}: {termination}"
        );
        // run_provider joins all three readers before returning anything but Timeout.
        // Independently observe that the descendant which retained both pipes is dead.
        let status = Command::new("python3")
            .args([
                "-c",
                r#"
import os,sys,time
pid=int(sys.argv[1]);deadline=time.monotonic()+3
while True:
 try: os.kill(pid,0)
 except ProcessLookupError: break
 assert time.monotonic()<deadline, 'owned descendant remained alive'
 time.sleep(.01)
"#,
                &descendant.to_string(),
            ])
            .status()
            .unwrap();
        assert!(status.success());
        owner.wait_for_phase(OwnerState::Revoked);
        assert!(std::fs::read_dir(&directory).unwrap().next().is_none());
        std::fs::remove_dir(directory).unwrap();
    }
}

#[cfg(test)]
mod claude_tests {
    use super::*;
    use crate::integrated::{Owner, OwnerState, ProviderKind, SubmissionOutcome};

    #[cfg(unix)]
    mod schedules {
        use super::*;
        use std::io::BufRead;

        const PROVIDER: &str = r#"
import json,sys,os,socket,select,signal
signal.alarm(20)
mode=os.environ['HERDR_FIXTURE_MODE'];session=os.environ['HERDR_FIXTURE_SESSION']
observer=socket.create_connection(('127.0.0.1',int(os.environ['HERDR_FIXTURE_OBSERVER'])))
sync=observer.makefile('rwb',buffering=0)
def observe(value):sync.write((value+'\n').encode())
def release():assert sync.readline()==b'continue\n'
def read():return json.loads(sys.stdin.buffer.readline())
def send(value):print(json.dumps(value),flush=True)
a=read();assert a['request']['subtype']=='initialize'
send({'type':'control_response','response':{'subtype':'success','request_id':'initialize',
 'pending_permission_requests':[],'pending_user_dialog_requests':[],
 'response':{'commands':[],'agents':[],'models':[],'output_style':'default'}}})
a=read();assert a['request']['subtype']=='get_binary_version'
send({'type':'control_response','response':{'subtype':'success','request_id':a['request_id'],'response':{'version':'2.1.276'}}})
observe('holding-input')
if mode=='partial':
 first=os.read(0,1);assert first==b'{'
 observe('partial-byte');release()
 remaining=sys.stdin.buffer.read()
 assert remaining and not remaining.endswith(b'\n'), 'write was not actually partial'
 observe('partial-captured')
 release()
elif mode=='queued':
 assert select.select([sys.stdin],[],[],5)[0]
 observe('input-buffered');release()
 a=read();assert a['type']=='user' and a['session_id']==session and a['parent_tool_use_id'] is None
 assert a['message']['content']=='old queued text'
 a['isReplay']=True;send(a);observe('late-replay')
 release()
elif mode=='replacement':
 release()
 assert not select.select([sys.stdin],[],[],0)[0], 'replacement inherited old input'
 observe('empty-input')
 a=read();assert a['type']=='user' and a['session_id']==session and a['parent_tool_use_id'] is None
 assert a['message']['content']=='new own text'
 assert a['message']['content'] not in str(sys.argv) and a['message']['content'] not in str(dict(os.environ))
 assert os.listdir('.')==[]
 observe('own-input');a['isReplay']=True;send(a)
 send({'type':'result','session_id':session,'subtype':'success'})
 sys.stdin.read()
elif mode=='approval':
 a=read();assert a['type']=='user' and a['session_id']==session
 assert a['message']['content']=='old queued text'
 a['isReplay']=True;send(a)
 send({'type':'control_request','request_id':'old-consent','request':{
  'subtype':'can_use_tool','tool_name':'Bash','tool_use_id':'old-tool',
  'input':{'command':'printf safe','timeout':2000}}})
 observe('old-card-issued');release()
 assert sys.stdin.buffer.read()==b'', 'retired card generated provider response'
 observe('no-old-decision');release()
else:raise AssertionError('unknown schedule')
"#;

        struct Fixture {
            owner: Arc<Owner>,
            ui: mpsc::SyncSender<Input>,
            observer: Option<BufReader<std::net::TcpStream>>,
            helper: Option<std::thread::JoinHandle<io::Result<()>>>,
            arrived: mpsc::Receiver<()>,
            release_cleanup: mpsc::SyncSender<()>,
            directory: std::path::PathBuf,
        }
        impl Fixture {
            fn new(mode: &str, token: &str) -> Self {
                let bootstrap = crate::platform::RecipientBootstrap::new().unwrap();
                let directory = std::env::temp_dir().join(format!(
                    "claude-schedule-{}",
                    crate::platform::recipient_random().unwrap()
                ));
                std::fs::create_dir(&directory).unwrap();
                let directory = directory.canonicalize().unwrap();
                let args = vec![
                    bootstrap.path().to_string_lossy().into_owned(),
                    bootstrap.nonce.clone(),
                    directory.to_string_lossy().into_owned(),
                ];
                let owner = Owner::launch(
                    ProviderKind::Claude,
                    RecipientIdentity {
                        server_instance: "schedule-server".into(),
                        recipient_token: token.into(),
                        terminal_id: "same-terminal".into(),
                    },
                    bootstrap,
                    std::process::id(),
                );
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                listener.set_nonblocking(true).unwrap();
                let mut command = Command::new("python3");
                command
                    .args(["-u", "-c", PROVIDER])
                    .env("HERDR_FIXTURE_MODE", mode)
                    .env(
                        "HERDR_FIXTURE_OBSERVER",
                        listener.local_addr().unwrap().port().to_string(),
                    )
                    .env("HERDR_FIXTURE_SESSION", token);
                let (ui, ui_rx) = mpsc::sync_channel(1);
                let (arrived_tx, arrived) = mpsc::sync_channel(1);
                let (release_cleanup, release_rx) = mpsc::sync_channel(1);
                let protocol = Protocol::Claude(super::super::super::claude::Claude::new(
                    args[2].clone(),
                    token.into(),
                ));
                let helper = std::thread::spawn(move || {
                    run_protocol(
                        &args,
                        command,
                        protocol,
                        false,
                        Some((arrived_tx, release_rx)),
                        Some(ui_rx),
                    )
                });
                let mut fixture = Self {
                    owner,
                    ui,
                    observer: None,
                    helper: Some(helper),
                    arrived,
                    release_cleanup,
                    directory,
                };
                let deadline = Instant::now() + Duration::from_secs(5);
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "fixture observer deadline");
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("fixture observer: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                fixture.observer = Some(BufReader::new(stream));
                fixture.expect("holding-input");
                fixture
                    .owner
                    .wait_for_phase(OwnerState::AwaitingSessionConfirmation);
                fixture
            }
            fn expect(&mut self, expected: &str) {
                let mut line = String::new();
                self.observer
                    .as_mut()
                    .unwrap()
                    .read_line(&mut line)
                    .unwrap();
                assert_eq!(line.trim_end(), expected);
            }
            fn release(&mut self) {
                self.observer
                    .as_mut()
                    .unwrap()
                    .get_mut()
                    .write_all(b"continue\n")
                    .unwrap();
            }
            fn retired(&self) {
                self.arrived.recv_timeout(Duration::from_secs(5)).unwrap();
                self.owner.wait_for_phase(OwnerState::Revoked);
            }
            fn finish(mut self, kind: io::ErrorKind) {
                self.owner.revoke();
                self.release_cleanup.try_send(()).unwrap();
                assert_eq!(
                    self.helper
                        .take()
                        .unwrap()
                        .join()
                        .unwrap()
                        .unwrap_err()
                        .kind(),
                    kind
                );
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                self.owner.revoke();
                let _ = self.release_cleanup.try_send(());
                if let Some(helper) = self.helper.take() {
                    let _ = helper.join();
                }
                let _ = std::fs::remove_dir(&self.directory);
            }
        }
        #[test]
        fn claude_buffered_and_partial_input_stay_with_retired_process() {
            for mode in ["queued", "partial"] {
                let mut old = Fixture::new(mode, "old-session");
                let text = if mode == "partial" {
                    format!("a{}", "\n".repeat(65535))
                } else {
                    "old queued text".into()
                };
                old.ui.send(Input::Text(text)).unwrap();
                old.expect(if mode == "partial" {
                    "partial-byte"
                } else {
                    "input-buffered"
                });
                if mode == "queued" {
                    old.owner.revoke();
                }
                old.retired();
                assert!(old.ui.send(Input::Text("old draft".into())).is_err());
                let mut replacement = Fixture::new("replacement", "new-session");
                old.release();
                old.expect(if mode == "partial" {
                    "partial-captured"
                } else {
                    "late-replay"
                });
                replacement.release();
                replacement.expect("empty-input");
                replacement
                    .ui
                    .send(Input::Decision(json!("old-consent"), "allow".into()))
                    .unwrap();
                replacement
                    .ui
                    .send(Input::Text("new own text".into()))
                    .unwrap();
                replacement.expect("own-input");
                replacement.owner.wait_for_phase(OwnerState::Idle);
                assert_eq!(old.owner.state(), OwnerState::Revoked);
                assert!(replacement
                    .owner
                    .codex_snapshot("same-terminal", Some("schedule-server"))
                    .exact_prompt
                    .is_none());
                replacement.finish(io::ErrorKind::UnexpectedEof);
                old.finish(if mode == "partial" {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::UnexpectedEof
                });
            }
        }

        #[test]
        fn claude_issued_card_and_old_ui_channel_cannot_transfer_to_replacement() {
            let mut old = Fixture::new("approval", "old-session");
            old.ui.send(Input::Text("old queued text".into())).unwrap();
            old.expect("old-card-issued");
            old.owner.wait_for_phase(OwnerState::PendingPermission);
            old.owner.revoke();
            old.retired();
            assert!(old
                .ui
                .send(Input::Decision(json!("old-consent"), "allow".into()))
                .is_err());
            assert!(old.ui.send(Input::Text("old unsent draft".into())).is_err());
            let mut replacement = Fixture::new("replacement", "new-session");
            replacement
                .ui
                .send(Input::Decision(json!("old-consent"), "allow".into()))
                .unwrap();
            // A second event crosses the one-slot queue only after the old card
            // decision has been processed by the replacement protocol.
            replacement
                .ui
                .send(Input::Decision(json!("barrier"), "deny".into()))
                .unwrap();
            replacement.release();
            replacement.expect("empty-input");
            assert_eq!(
                replacement.owner.state(),
                OwnerState::AwaitingSessionConfirmation
            );
            old.release();
            old.expect("no-old-decision");
            replacement
                .ui
                .send(Input::Text("new own text".into()))
                .unwrap();
            replacement.expect("own-input");
            replacement.owner.wait_for_phase(OwnerState::Idle);
            replacement.finish(io::ErrorKind::UnexpectedEof);
            old.finish(io::ErrorKind::UnexpectedEof);
        }
    }
    #[test]
    fn revoked_claude_decision_enters_helper_error_teardown() {
        let mut claude = super::super::claude::Claude::new("/tmp/trusted".into(), "fixed".into());
        claude.state = OwnerState::Revoked;
        let mut protocol = Protocol::Claude(claude);
        assert!(protocol.decision(&json!("stale"), "allow").is_err());
        assert_eq!(protocol.state(), OwnerState::Revoked);
    }
    const SCRIPT: &str = r#"
import json,sys,os,socket,subprocess,select
child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
observer=socket.create_connection(('127.0.0.1',int(os.environ['HERDR_FIXTURE_OBSERVER'])))
sync=observer.makefile('rwb',buffering=0)
def observe(s):sync.write((str(s)+'\n').encode())
def release():assert sync.readline()==b'continue\n'
def send(x):print(json.dumps(x),flush=True)
def read():return json.loads(sys.stdin.readline())
observe(child.pid)
a=read();assert a=={'type':'control_request','request_id':'initialize','request':{'subtype':'initialize'}}
send({'type':'control_response','response':{'subtype':'success','request_id':'initialize','pending_permission_requests':[],'pending_user_dialog_requests':[],'response':{'commands':[],'agents':[],'models':[],'output_style':'default'}}})
a=read();assert a['request']['subtype']=='get_binary_version'
send({'type':'control_response','response':{'subtype':'success','request_id':a['request_id'],'response':{'version':'2.1.276'}}})
a=read();assert a['type']=='user';assert a['session_id']=='fixed-fixture-session';assert a['parent_tool_use_id'] is None
text=a['message']['content'];assert text=='private-claude-fixture\nexact text'
assert text not in str(sys.argv) and text not in str(dict(os.environ));assert os.listdir('.')==[]
observe('first-input')
release()
assert not select.select([sys.stdin],[],[],0)[0], 'second bootstrap reached provider'
mode=os.environ['HERDR_FIXTURE_MODE']
if mode=='reset':send({'type':'conversation_reset','new_conversation_id':'replacement'})
elif mode=='reset-after-replay':
 a['isReplay']=True;send(a);send({'type':'conversation_reset','new_conversation_id':'replacement'})
elif mode=='wrong':
 a['isReplay']=True;a['session_id']='replacement';send(a)
elif mode=='result-first':send({'type':'result','session_id':a['session_id'],'subtype':'success'})
elif mode=='overflow':
 try:print('x'*1048577,flush=True)
 except BrokenPipeError:pass
elif mode=='stderr':
 try:sys.stderr.write('x'*65537);sys.stderr.flush()
 except BrokenPipeError:pass
else:
 send({'type':'system','subtype':'init','session_id':a['session_id'],'uuid':'init-first','cwd':os.getcwd(),'claude_code_version':'2.1.276','permissionMode':'default'})
 send({'type':'rate_limit_event','session_id':a['session_id'],'uuid':'rate-before','rate_limit_info':{'status':'allowed'}})
 a['isReplay']=True;send(a)
 send({'type':'rate_limit_event','session_id':a['session_id'],'uuid':'rate-after','rate_limit_info':{'status':'allowed_warning','utilization':0.9}})
 send({'type':'control_request','request_id':'consent','request':{'subtype':'can_use_tool','tool_name':'Bash','tool_use_id':'tool-1','input':{'command':'printf safe','timeout':2000}}})
 consent_id='consent'
 if mode=='cancel':
  observe('cancel-ready');release()
  send({'type':'control_cancel_request','request_id':'consent'})
  observe('cancelled');release()
  assert not select.select([sys.stdin],[],[],0)[0], 'stale card generated response'
  consent_id='replacement-consent'
  send({'type':'control_request','request_id':consent_id,'request':{'subtype':'can_use_tool','tool_name':'Bash','tool_use_id':'tool-2','input':{'command':'printf safe','timeout':2000}}})
 send({'type':'tool_progress','session_id':a['session_id'],'uuid':'heartbeat','tool_use_id':'tool-1','tool_name':'Bash','parent_tool_use_id':None,'elapsed_time_seconds':1,'heartbeat':True})
 reply=read()
 expected={'behavior':'deny','message':'User declined integrated operation'} if mode=='deny' else {'behavior':'allow','updatedInput':{'command':'printf safe','timeout':2000}}
 assert reply=={'type':'control_response','response':{'subtype':'success','request_id':consent_id,'response':expected}}
 send(reply)
 send({'type':'user','session_id':a['session_id'],'uuid':'tool-result','parent_tool_use_id':None,'message':{'role':'user','content':[{'type':'tool_result','tool_use_id':'tool-1','content':'declined' if mode=='deny' else 'safe','is_error':mode=='deny'}]},'tool_use_result':'declined' if mode=='deny' else {'stdout':'safe'}})
 send({'type':'assistant','session_id':a['session_id'],'message':{'role':'assistant','content':[{'type':'text','text':'Tool settled.'}]}})
 observe('approved-original')
 send({'type':'result','session_id':a['session_id'],'subtype':'success'})
 b=read();assert b['type']=='user' and b['uuid']!=a['uuid'];assert b['session_id']==a['session_id'];assert b['message']['content']=='private-claude-fixture\nexact text'
 observe('second-input');release()
 send({'type':'system','subtype':'init','session_id':b['session_id'],'uuid':'init-second','cwd':os.getcwd(),'claude_code_version':'2.1.276','permissionMode':'default'})
 b['isReplay']=True;send(b)
 send({'type':'result','session_id':b['session_id'],'subtype':'success'})
sys.stdin.read()
"#;
    #[test]
    fn claude_fake_process_bootstrap_consent_shared_admission_and_owned_cleanup() {
        fixture("accept");
        fixture("deny");
        fixture("cancel");
    }
    #[test]
    fn claude_fake_process_reset_mismatch_completion_and_flood_retire() {
        for mode in [
            "reset",
            "reset-after-replay",
            "wrong",
            "result-first",
            "overflow",
            "stderr",
        ] {
            fixture(mode);
        }
    }
    fn fixture(mode: &str) {
        use std::io::BufRead;
        let Ok(bootstrap) = crate::platform::RecipientBootstrap::new() else {
            return;
        };
        let directory = std::env::temp_dir().join(format!(
            "herdr-claude-fixture-{}",
            crate::platform::recipient_random().unwrap()
        ));
        std::fs::create_dir(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        let args = vec![
            bootstrap.path().to_string_lossy().into_owned(),
            bootstrap.nonce.clone(),
            directory.to_string_lossy().into_owned(),
        ];
        let owner = Owner::launch(
            ProviderKind::Claude,
            RecipientIdentity {
                server_instance: "fixture-server".into(),
                recipient_token: "fixture-recipient".into(),
                terminal_id: "fixture-terminal".into(),
            },
            bootstrap,
            std::process::id(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut command = Command::new("python3");
        command
            .args(["-u", "-c", SCRIPT])
            .env(
                "HERDR_FIXTURE_OBSERVER",
                listener.local_addr().unwrap().port().to_string(),
            )
            .env("HERDR_FIXTURE_MODE", mode);
        let (ui_tx, ui_rx) = mpsc::sync_channel(1);
        let protocol = Protocol::Claude(super::super::claude::Claude::new(
            args[2].clone(),
            "fixed-fixture-session".into(),
        ));
        let helper = std::thread::spawn(move || {
            run_protocol(&args, command, protocol, false, None, Some(ui_rx))
        });
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut observer = BufReader::new(stream);
        fn observed(reader: &mut BufReader<std::net::TcpStream>) -> String {
            let mut s = String::new();
            reader.read_line(&mut s).unwrap();
            s.trim_end().into()
        }
        let descendant: u32 = observed(&mut observer).parse().unwrap();
        owner.wait_for_phase(OwnerState::AwaitingSessionConfirmation);
        assert!(owner
            .codex_snapshot("fixture-terminal", Some("fixture-server"))
            .exact_prompt
            .is_none());
        let text = "private-claude-fixture\nexact text";
        ui_tx.send(Input::Text(text.into())).unwrap();
        assert_eq!(observed(&mut observer), "first-input");
        owner.wait_for_phase(OwnerState::ActiveTurn);
        assert_eq!(
            owner.reserve(&owner.identity, "desktop", text).unwrap_err(),
            SubmissionOutcome::rejected("unsupported_recipient")
        );
        ui_tx
            .send(Input::Text("second-bootstrap-must-not-write".into()))
            .unwrap();
        // A third UI event blocks until the single consumer has processed the second.
        ui_tx
            .send(Input::Decision(json!("nonexistent"), "allow".into()))
            .unwrap();
        observer.get_mut().write_all(b"continue\n").unwrap();
        if matches!(mode, "accept" | "deny" | "cancel") {
            owner.wait_for_phase(OwnerState::PendingPermission);
            let consent_id = if mode == "cancel" {
                assert_eq!(observed(&mut observer), "cancel-ready");
                observer.get_mut().write_all(b"continue\n").unwrap();
                assert_eq!(observed(&mut observer), "cancelled");
                owner.wait_for_phase(OwnerState::ActiveTurn);
                ui_tx
                    .send(Input::Decision(json!("consent"), "allow".into()))
                    .unwrap();
                ui_tx
                    .send(Input::Decision(json!("nonexistent"), "allow".into()))
                    .unwrap();
                observer.get_mut().write_all(b"continue\n").unwrap();
                owner.wait_for_phase(OwnerState::PendingPermission);
                "replacement-consent"
            } else {
                "consent"
            };
            ui_tx
                .send(Input::Decision(
                    json!(consent_id),
                    if mode == "deny" { "deny" } else { "allow" }.into(),
                ))
                .unwrap();
            assert_eq!(observed(&mut observer), "approved-original");
            owner.wait_for_phase(OwnerState::Idle);
            assert!(owner
                .codex_snapshot("fixture-terminal", Some("fixture-server"))
                .exact_prompt
                .is_none());
            ui_tx.send(Input::Text(text.into())).unwrap();
            assert_eq!(observed(&mut observer), "second-input");
            owner.wait_for_phase(OwnerState::ActiveTurn);
            observer.get_mut().write_all(b"continue\n").unwrap();
            owner.wait_for_phase(OwnerState::Idle);
            owner.revoke();
        }
        let error = helper.join().unwrap().unwrap_err();
        assert_eq!(
            error.kind(),
            if matches!(mode, "accept" | "deny" | "cancel") {
                io::ErrorKind::UnexpectedEof
            } else if mode == "stderr" {
                io::ErrorKind::Other
            } else {
                io::ErrorKind::InvalidData
            },
            "mode {mode}: {error}"
        );
        owner.wait_for_phase(OwnerState::Revoked);
        let status=Command::new("python3").args(["-c", "import os,sys,time\npid=int(sys.argv[1]);end=time.monotonic()+3\nwhile True:\n try:os.kill(pid,0)\n except ProcessLookupError:break\n assert time.monotonic()<end,'owned descendant leaked'\n time.sleep(.01)", &descendant.to_string()]).status().unwrap();
        assert!(status.success());
        assert!(std::fs::read_dir(&directory).unwrap().next().is_none());
        std::fs::remove_dir(directory).unwrap();
    }
}
