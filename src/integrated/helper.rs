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

pub(crate) fn run(args: &[String]) -> io::Result<()> {
    let mut command = Command::new("codex");
    command.args(["app-server", "--listen", "stdio://"]);
    run_provider(args, command, true)
}

fn run_provider(args: &[String], mut command: Command, render_enabled: bool) -> io::Result<()> {
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
        let mut codex = Codex::new(cwd.clone());
        write_frame(&mut input, &Codex::initialize(), INPUT_LIMIT)?;
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
                if codex.state == super::owner::OwnerState::Starting
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
                        effects.extend(codex.submit(SubmissionOrigin::Remote(id), text));
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
                            codex
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
                                codex.submit(SubmissionOrigin::Local(local_sequence), text),
                            );
                        }
                        Input::Decision(id, decision) => {
                            effects.extend(codex.decision(&id, &decision))
                        }
                    }
                }
                for effect in effects.drain(..) {
                    match effect {
                        Effect::Write(frame) => {
                            if frame["method"] == "turn/start" {
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
                            view.lock().unwrap().status = format!("Codex integrated — {state:?}");
                            write_frame(
                                &mut control,
                                &json!({"kind":"state","identity":identity,"state":state}),
                                CONTROL_LIMIT,
                            )?;
                        }
                    }
                }
                view.lock().unwrap().cards = codex.approvals.cards();
                std::thread::sleep(Duration::from_millis(5));
            }
        })();
        {
            let mut view = view.lock().unwrap();
            view.ended = true;
            view.status = "Recipient revoked; never replay pending input".into();
        }
        let _ = control.shutdown(std::net::Shutdown::Both);
        session
    })();
    let _ = control.shutdown(std::net::Shutdown::Both);
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
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrated::{Owner, OwnerState, SubmissionOutcome};
    const PROVIDER: &str = r#"
import json,sys,os,subprocess
# A descendant deliberately retains the provider pipes until owned group cleanup.
subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"])
read=lambda:json.loads(sys.stdin.readline())
def send(x): print(json.dumps(x),flush=True)
a=read();send({'id':a['id'],'result':{'userAgent':'codex/0.154.0'}})
assert read()['method']=='initialized'
a=read();send({'id':a['id'],'result':{'thread':{'id':'fixed'},'cwd':os.getcwd(),'approvalPolicy':'on-request','sandbox':{'type':'readOnly'}}})
a=read();assert a['method']=='turn/start';assert a['params']['threadId']=='fixed'
text=a['params']['input'][0]['text']
assert text not in str(sys.argv) and text not in str(dict(os.environ))
assert os.listdir('.')==[]
mode=os.environ['HERDR_FIXTURE_MODE']
if mode=='wrong': send({'method':'item/agentMessage/delta','params':{'threadId':'replacement','delta':'wrong'}})
elif mode=='reset':send({'method':'thread/reset','params':{'threadId':'fixed'}})
elif mode=='overflow': print('x'*1048577,flush=True)
else:
 send({'id':a['id'],'result':{'turn':{'id':'accepted-turn'}}})
 send({'method':'turn/completed','params':{'threadId':'fixed','turn':{'id':'accepted-turn'}}})
 # With no renderer/client attached, the process remains alive to admit a second input.
 a=read();send({'id':a['id'],'result':{'turn':{'id':'second-turn'}}})
 # Wait for owned cleanup rather than racing the acknowledgment with process exit.
 sys.stdin.read()
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
        let owner = Owner::launch(
            RecipientIdentity {
                server_instance: "test-server".into(),
                recipient_token: "test-recipient".into(),
                terminal_id: "test-terminal".into(),
            },
            bootstrap,
            std::process::id(),
        );
        let mut provider = Command::new("python3");
        provider
            .args(["-u", "-c", PROVIDER])
            .env("HERDR_FIXTURE_MODE", mode);
        let helper = std::thread::spawn(move || run_provider(&args, provider, false));
        owner.wait_for_phase(OwnerState::Idle);
        let prompt = "private-fixture-body-79c6\nquote ' \" end";
        let result = owner.reserve(&owner.identity, "request1", prompt).unwrap();
        owner.forward("request1", prompt);
        if mode == "accept" {
            assert!(matches!(
                owner.wait(result),
                SubmissionOutcome::Accepted { .. }
            ));
            owner.wait_for_phase(OwnerState::Idle);
            let result = owner.reserve(&owner.identity, "request2", prompt).unwrap();
            owner.forward("request2", prompt);
            assert!(matches!(
                owner.wait(result),
                SubmissionOutcome::Accepted { .. }
            ));
            owner.revoke();
        } else {
            assert_eq!(owner.wait(result), SubmissionOutcome::Unknown);
        }
        let _ = helper.join().unwrap();
        owner.wait_for_phase(OwnerState::Revoked);
        assert!(std::fs::read_dir(&directory).unwrap().next().is_none());
        std::fs::remove_dir(directory).unwrap();
    }
}
