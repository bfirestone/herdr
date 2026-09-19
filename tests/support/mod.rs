use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

static PID_REGISTRY: OnceLock<Mutex<std::collections::HashMap<u32, TestProcessIdentity>>> =
    OnceLock::new();
static RUNTIME_DIR_REGISTRY: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
static INIT: Once = Once::new();
static CLEANUP_GUARD: OnceLock<CleanupGuard> = OnceLock::new();
const WATCHDOG_SCAN_INTERVAL: Duration = Duration::from_secs(1);
const RUNTIME_OWNER_MARKER: &str = ".herdr-test-owner-pid";
pub const CURRENT_PROTOCOL: u32 = 22;
pub const CURRENT_ENDPOINT_PROTOCOL_GENERATION: u32 = 1;
pub const SERVER_MESSAGE_SERVER_SHUTDOWN: u32 = 3;
pub const SERVER_MESSAGE_ENDPOINT_CONTROL: u32 = 20;
pub const SERVER_MESSAGE_PANE_SURFACE: u32 = 13;
pub const SERVER_MESSAGE_SEMANTIC_NOTIFICATION: u32 = 14;
pub const SERVER_MESSAGE_PANE_SURFACE_PATCH: u32 = 19;
const CLIENT_MESSAGE_CLIENT_SHELL_PANE_INPUT: u32 = 13;
const CLIENT_MESSAGE_CLIENT_SHELL_FOCUS: u32 = 18;
const CLIENT_MESSAGE_ENDPOINT_CONTROL: u32 = 20;

// A handoff fixture owns detached imports by exact executable, birth identity,
// and registered data directory. PID reuse is rechecked before each signal;
// this is not an atomic OS process-handle guarantee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestProcessIdentity {
    pub pid: u32,
    pub birth: (u64, u64),
    executable: PathBuf,
    import_socket: Option<PathBuf>,
    runtime_dir: Option<PathBuf>,
}

#[derive(Default)]
struct HandoffOwnership {
    base: PathBuf,
    owner_birth: (u64, u64),
    data_dirs: HashSet<PathBuf>,
    producers: Vec<TestProcessIdentity>,
    imports: Vec<TestProcessIdentity>,
    finished: bool,
    borrowed: bool,
    terminated_servers: usize,
    unresolved_startup: Option<String>,
    starting: bool,
    #[cfg(test)]
    inspection_failure: bool,
    #[cfg(test)]
    executable_failure: Option<(u32, i32)>,
}

type FixtureState = std::sync::Arc<Mutex<HandoffOwnership>>;
static HANDOFF_FIXTURES: OnceLock<Mutex<std::collections::HashMap<PathBuf, FixtureState>>> =
    OnceLock::new();

fn fixture_registry(
) -> std::sync::MutexGuard<'static, std::collections::HashMap<PathBuf, FixtureState>> {
    HANDOFF_FIXTURES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

pub struct HandoffFixture {
    base: PathBuf,
    state: FixtureState,
}

impl std::ops::Deref for HandoffFixture {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.base
    }
}

impl AsRef<Path> for HandoffFixture {
    fn as_ref(&self) -> &Path {
        &self.base
    }
}

impl HandoffFixture {
    pub fn create(base: PathBuf) -> std::io::Result<Self> {
        let owner_birth = test_process_birth(std::process::id())?
            .ok_or_else(|| bad_inspection("missing test-owner birth identity"))?;
        // Exclusive creation is essential: never adopt a stale fixture.
        fs::create_dir(&base)?;
        fs::write(
            base.join("fixture-owner.json"),
            serde_json::to_vec(&(std::process::id(), owner_birth))?,
        )?;
        fs::write(base.join("producers.jsonl"), [])?;
        let state = std::sync::Arc::new(Mutex::new(HandoffOwnership {
            base: base.clone(),
            owner_birth,
            ..Default::default()
        }));
        fixture_registry().insert(base.clone(), state.clone());
        ensure_cleanup_hooks();
        register_runtime_dir(&base.join("runtime"));
        let fixture = Self { base, state };
        register_fixture_data_dir(
            &fixture.state,
            &fixture.base,
            &fixture.base.join("config/herdr-dev"),
        )?;
        register_fixture_data_dir(
            &fixture.state,
            &fixture.base,
            &fixture.base.join("config/herdr"),
        )?;
        Ok(fixture)
    }

    // Only the dedicated nested test may borrow a parent's exclusively allocated
    // fixture. The parent keeps deletion and emergency-cleanup responsibility.
    pub fn borrow_from_parent(base: PathBuf, parent_pid: u32) -> std::io::Result<Self> {
        let (owner, birth): (u32, (u64, u64)) =
            serde_json::from_slice(&fs::read(base.join("fixture-owner.json"))?)?;
        if owner != parent_pid || test_process_birth(owner)? != Some(birth) {
            return Err(bad_inspection("nested fixture parent identity changed"));
        }
        let state = std::sync::Arc::new(Mutex::new(HandoffOwnership {
            base: base.clone(),
            owner_birth: birth,
            borrowed: true,
            ..Default::default()
        }));
        fixture_registry().insert(base.clone(), state.clone());
        ensure_cleanup_hooks();
        let fixture = Self { base, state };
        for directory in ["config/herdr-dev", "config/herdr"] {
            register_fixture_data_dir(
                &fixture.state,
                &fixture.base,
                &fixture.base.join(directory),
            )?;
        }
        Ok(fixture)
    }

    #[cfg(test)]
    pub fn inject_executable_failure(&self, pid: u32, error: Option<i32>) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .executable_failure = error.map(|error| (pid, error));
    }

    #[cfg(test)]
    pub fn inject_inspection_failure(&self, fail: bool) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .inspection_failure = fail;
    }

    // Caller has confirmed its unreaped direct helper is stopped. Capturing
    // children now closes the spawn-to-journal window before killing that helper.
    pub fn capture_stopped_helper_children(&self, helper_pid: u32) -> std::io::Result<()> {
        let helper_birth = test_process_birth(helper_pid)?
            .ok_or_else(|| bad_inspection("stopped helper identity absent"))?;
        let end = Instant::now() + Duration::from_secs(3);
        for pid in all_process_pids()? {
            if Instant::now() >= end {
                return Err(bad_inspection("helper child inventory deadline"));
            }
            let Some(birth) = test_process_birth(pid)? else {
                continue;
            };
            if birth < helper_birth {
                continue;
            }
            let Some(parent) = resolve_identity_inspection(
                pid,
                birth,
                "initial helper child parent",
                test_process_parent(pid),
                test_process_birth,
            )?
            else {
                continue;
            };
            if parent != helper_pid {
                continue;
            }
            // A freshly forked direct child may still show the helper executable.
            // Wait only for this proven child to settle to the exact Cargo binary.
            if let Some(identity) = settled_herdr_identity_before(pid, end)? {
                if identity.birth != birth {
                    continue;
                }
                let Some(parent) = resolve_identity_inspection(
                    pid,
                    birth,
                    "final helper child parent",
                    test_process_parent(pid),
                    test_process_birth,
                )?
                else {
                    continue;
                };
                if test_process_birth(pid)? != Some(birth) {
                    continue;
                }
                if parent != helper_pid {
                    return Err(bad_inspection("helper child parent changed during capture"));
                }
                // Keep each proven child even if a later candidate cannot be
                // inspected or the bounded inventory fails.
                self.state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .producers
                    .push(identity.clone());
                record_handoff_producer(&self.base.join("config"), &identity)?;
            }
        }
        if test_process_birth(helper_pid)? != Some(helper_birth) {
            return Err(bad_inspection(
                "helper changed during stopped-child inventory",
            ));
        }
        Ok(())
    }

    pub fn clear_reaped_helper_startup(&self) -> std::io::Result<()> {
        match fs::remove_file(self.base.join("pending-startup")) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub fn set_nested_helper_active(&self, active: bool) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .starting = active;
    }

    pub fn terminated_servers(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .terminated_servers
    }

    pub fn finish(&self) -> std::io::Result<()> {
        finish_handoff_fixture(&self.state)
    }
}

#[cfg(test)]
pub fn clear_handoff_inspection_failure(base: &Path) {
    let state = fixture_registry()
        .get(base)
        .cloned()
        .expect("retained fixture ownership");
    state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .inspection_failure = false;
}

impl Drop for HandoffFixture {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            if std::thread::panicking() {
                eprintln!(
                    "handoff fixture {} cleanup unresolved: {error}",
                    self.base.display()
                );
            } else {
                panic!(
                    "handoff fixture {} cleanup unresolved: {error}",
                    self.base.display()
                );
            }
        }
    }
}

fn write_fixture_ledger(record: serde_json::Value) -> std::io::Result<()> {
    if let Some(path) = std::env::var_os("HERDR_TEST_FIXTURE_LEDGER") {
        // Serialize before appending; the supervisor treats incomplete records as errors.
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        file.write_all(format!("{record}\n").as_bytes())?;
    }
    Ok(())
}

fn register_fixture_data_dir(
    state: &FixtureState,
    base: &Path,
    path: &Path,
) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    let canonical = fs::canonicalize(path)?;
    state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .data_dirs
        .extend([path.to_path_buf(), canonical]);
    write_fixture_ledger(serde_json::json!({"base": base, "data_dir": path}))
}

pub fn register_handoff_data_dir(config_home: &Path, session: Option<&str>) {
    let base = config_home.parent().expect("fixture config parent");
    let state = fixture_registry()
        .get(base)
        .cloned()
        .expect("pre-spawn fixture guard");
    let mut path = config_home.join("herdr-dev");
    if let Some(name) = session {
        path = path.join("sessions").join(name);
    }
    register_fixture_data_dir(&state, base, &path).expect("register handoff data directory");
}

pub fn record_teardown_helper(pid: u32) {
    let identity = test_process_identity(pid)
        .expect("inspect helper child")
        .expect("live helper child");
    write_fixture_ledger(serde_json::json!({"pid": pid, "birth": identity.birth, "executable": identity.executable, "kind": "helper"})).expect("record helper child");
}

pub fn set_handoff_starting(config_home: &Path, starting: bool) {
    let state = fixture_registry()
        .get(config_home.parent().unwrap())
        .cloned()
        .expect("pre-spawn fixture guard");
    let marker = config_home.parent().unwrap().join("pending-startup");
    if starting {
        fs::write(&marker, b"unrecorded child startup").expect("retain pending child startup");
    } else {
        match fs::remove_file(marker) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("clear pending child startup: {error}"),
        }
    }
    state.lock().unwrap_or_else(|e| e.into_inner()).starting = starting;
}

pub fn retain_handoff_startup_failure(config_home: &Path, failure: &str) {
    let state = fixture_registry()
        .get(config_home.parent().unwrap())
        .cloned();
    if let Some(state) = state {
        state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unresolved_startup = Some(failure.to_owned());
    }
}

pub fn record_handoff_producer(
    config_home: &Path,
    identity: &TestProcessIdentity,
) -> std::io::Result<()> {
    let base = config_home.parent().expect("fixture parent");
    let record = serde_json::json!({"pid": identity.pid, "birth": identity.birth,
        "executable": identity.executable});
    let mut journal = fs::OpenOptions::new()
        .append(true)
        .open(base.join("producers.jsonl"))?;
    writeln!(journal, "{record}")
}

pub fn register_handoff_producer(config_home: &Path, identity: &TestProcessIdentity) {
    let state = fixture_registry()
        .get(config_home.parent().unwrap())
        .cloned()
        .expect("pre-spawn fixture guard");
    let pid = identity.pid;
    record_handoff_producer(config_home, identity)
        .expect("record parent-owned producer before registration");
    set_handoff_starting(config_home, false);
    {
        let mut ownership = state.lock().unwrap_or_else(|e| e.into_inner());
        ownership.producers.push(identity.clone());
        ownership.starting = false;
    }
    write_fixture_ledger(
        serde_json::json!({"pid": pid, "birth": [identity.birth.0, identity.birth.1], "executable": identity.executable}),
    )
    .expect("record direct child identity");
}

fn bad_inspection(message: &str) -> std::io::Error {
    std::io::Error::other(message)
}

#[cfg(target_os = "macos")]
pub fn test_process_birth(pid: u32) -> std::io::Result<Option<(u64, u64)>> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(bad_inspection("invalid PID"));
    }
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as i32;
    let count = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut _,
            size,
        )
    };
    if count == size {
        // Zombies have exited; waitpid in the bounded reap path consumes children.
        return Ok((info.pbi_status != 5).then_some((info.pbi_start_tvsec, info.pbi_start_tvusec)));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(None)
    } else {
        Err(error)
    }
}

#[cfg(target_os = "linux")]
pub fn test_process_birth(pid: u32) -> std::io::Result<Option<(u64, u64)>> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(bad_inspection("invalid PID"));
    }
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .ok_or_else(|| bad_inspection("invalid proc stat"))?
        .1
        .split_whitespace()
        .collect();
    if fields.first() == Some(&"Z") {
        return Ok(None);
    }
    let start = fields
        .get(19)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| bad_inspection("missing process start time"))?;
    Ok(Some((start, 0)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn test_process_birth(_pid: u32) -> std::io::Result<Option<(u64, u64)>> {
    Err(bad_inspection("process identity unsupported on this OS"))
}

#[cfg(target_os = "macos")]
fn retry_macos_inspection<T>(
    pid: u32,
    operation: &str,
    mut inspect: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let mut failure = match inspect() {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    if !matches!(
        failure.raw_os_error(),
        Some(libc::EINVAL | libc::EIO | libc::ESRCH)
    ) {
        return Err(failure);
    }
    let Some(birth) = test_process_birth(pid)? else {
        return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
    };
    // These native reads can race exit or metadata changes. Only confirmed exit
    // or changed birth means absence; persistent live uncertainty is an error.
    for _ in 0..4 {
        thread::sleep(Duration::from_millis(10));
        if test_process_birth(pid)? != Some(birth) {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
        }
        match inspect() {
            Ok(value) => return Ok(value),
            Err(error) => failure = error,
        }
        if !matches!(
            failure.raw_os_error(),
            Some(libc::EINVAL | libc::EIO | libc::ESRCH)
        ) {
            break;
        }
    }
    if test_process_birth(pid)? != Some(birth) {
        return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
    }
    Err(bad_inspection(&format!(
        "{operation} failed for live PID {pid} birth {birth:?}: {failure}"
    )))
}

fn process_executable(pid: u32) -> std::io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        retry_macos_inspection(pid, "proc_pidpath", || {
            let mut buf = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
            let size = unsafe {
                libc::proc_pidpath(pid as i32, buf.as_mut_ptr() as *mut _, buf.len() as u32)
            };
            if size <= 0 {
                return Err(std::io::Error::last_os_error());
            }
            let end = buf
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| bad_inspection("unterminated executable"))?;
            Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..end])))
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        fs::read_link(format!("/proc/{pid}/exe"))
    }
}

fn test_process_parent(pid: u32) -> std::io::Result<u32> {
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        let count = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut _,
                size,
            )
        };
        if count != size {
            return Err(std::io::Error::last_os_error());
        }
        Ok(info.pbi_ppid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        stat.rsplit_once(')')
            .and_then(|(_, fields)| fields.split_whitespace().nth(1))
            .and_then(|parent| parent.parse().ok())
            .ok_or_else(|| bad_inspection("invalid proc parent"))
    }
}

pub fn test_process_identity(pid: u32) -> std::io::Result<Option<TestProcessIdentity>> {
    test_process_identity_from(pid, test_process_birth, process_executable)
}

fn test_process_identity_from(
    pid: u32,
    mut read_birth: impl FnMut(u32) -> std::io::Result<Option<(u64, u64)>>,
    mut read_executable: impl FnMut(u32) -> std::io::Result<PathBuf>,
) -> std::io::Result<Option<TestProcessIdentity>> {
    let Some(birth) = read_birth(pid)
        .map_err(|error| bad_inspection(&format!("initial identity birth PID {pid}: {error}")))?
    else {
        return Ok(None);
    };
    let Some(executable) = resolve_identity_inspection(
        pid,
        birth,
        "identity executable",
        read_executable(pid),
        &mut read_birth,
    )?
    else {
        return Ok(None);
    };
    if read_birth(pid).map_err(|error| {
        bad_inspection(&format!(
            "final identity birth PID {pid} birth {birth:?}: {error}"
        ))
    })? != Some(birth)
    {
        return Ok(None);
    }
    Ok(Some(TestProcessIdentity {
        pid,
        birth,
        executable,
        import_socket: None,
        runtime_dir: None,
    }))
}

// An errno alone never establishes exit. Compare against the captured birth,
// including when a metadata probe failed before its normal final identity check.
fn resolve_identity_inspection<T>(
    pid: u32,
    birth: (u64, u64),
    operation: &str,
    result: std::io::Result<T>,
    mut read_birth: impl FnMut(u32) -> std::io::Result<Option<(u64, u64)>>,
) -> std::io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) => match read_birth(pid) {
            Ok(current) if current != Some(birth) => Ok(None),
            Ok(_) => Err(bad_inspection(&format!(
                "{operation} PID {pid} birth {birth:?}: {error}; recorded identity remains live"
            ))),
            Err(recheck) => Err(bad_inspection(&format!(
                "{operation} PID {pid} birth {birth:?}: {error}; birth recheck failed: {recheck}"
            ))),
        },
    }
}

// macOS can briefly report the spawning executable after spawn() returns.
// The caller keeps its direct Child guard armed until this identity settles.
pub fn settled_herdr_identity(pid: u32) -> std::io::Result<Option<TestProcessIdentity>> {
    settled_herdr_identity_before(pid, Instant::now() + Duration::from_secs(2))
}

fn settled_herdr_identity_before(
    pid: u32,
    deadline: Instant,
) -> std::io::Result<Option<TestProcessIdentity>> {
    let Some(birth) = test_process_birth(pid)? else {
        return Ok(None);
    };
    loop {
        if Instant::now() >= deadline {
            return Err(bad_inspection(
                "child executable settlement deadline exceeded",
            ));
        }
        let Some(identity) = test_process_identity(pid)? else {
            return Ok(None);
        };
        if identity.birth != birth {
            return Err(bad_inspection("child birth changed during startup"));
        }
        if is_test_herdr_binary(&identity.executable) {
            return Ok(Some(identity));
        }
        if Instant::now() >= deadline {
            return Err(bad_inspection(
                "child executable did not settle to Cargo Herdr",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(any(target_os = "macos", test))]
fn decode_procargs(buf: &[u8]) -> std::io::Result<Vec<String>> {
    let argc = i32::from_ne_bytes(
        buf.get(..4)
            .ok_or_else(|| bad_inspection("missing argc"))?
            .try_into()
            .unwrap(),
    );
    if !(1..=4096).contains(&argc) {
        return Err(bad_inspection("invalid argc"));
    }
    let mut offset = 4 + buf[4..]
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| bad_inspection("missing executable terminator"))?;
    while buf.get(offset) == Some(&0) {
        offset += 1;
    }
    let mut args = Vec::new();
    for _ in 0..argc {
        let tail = buf
            .get(offset..)
            .ok_or_else(|| bad_inspection("truncated argv"))?;
        let end = tail
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| bad_inspection("unterminated argv"))?;
        args.push(
            std::str::from_utf8(&tail[..end])
                .map_err(|_| bad_inspection("invalid argv encoding"))?
                .to_owned(),
        );
        offset += end + 1;
    }
    // Do not decode or log the environment tail (or the import token).
    Ok(args)
}

#[cfg(target_os = "macos")]
fn handoff_argv(pid: u32) -> std::io::Result<Vec<String>> {
    retry_macos_inspection(pid, "KERN_PROCARGS2", || {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as i32];
        let mut buf = vec![0u8; 1024 * 1024];
        let mut size = buf.len();
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buf.as_mut_ptr() as *mut _,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        buf.truncate(size);
        decode_procargs(&buf)
    })
}

#[cfg(not(target_os = "macos"))]
fn handoff_argv(pid: u32) -> std::io::Result<Vec<String>> {
    read_cmdline(pid)
}

fn exact_import_socket(args: &[String], dirs: &HashSet<PathBuf>) -> Option<PathBuf> {
    if args.len() != 5 || args[1] != "server" || args[2] != "--handoff-import" {
        return None;
    }
    let socket = Path::new(&args[3]);
    if !socket.is_absolute() || args[3].split('/').any(|part| part == "." || part == "..") {
        return None;
    }
    let name = socket.file_name()?.to_str()?;
    let pid = name.strip_prefix("herdr-handoff-")?.strip_suffix(".sock")?;
    if pid.is_empty()
        || !pid.bytes().all(|b| b.is_ascii_digit())
        || !(1..=i32::MAX as u32).contains(&pid.parse::<u32>().ok()?)
    {
        return None;
    }
    let parent = socket.parent()?;
    if !dirs.contains(parent)
        && !fs::canonicalize(parent)
            .ok()
            .is_some_and(|p| dirs.contains(&p))
    {
        return None;
    }
    Some(socket.to_path_buf())
}

fn all_process_pids() -> std::io::Result<Vec<u32>> {
    #[cfg(target_os = "macos")]
    {
        let mut capacity = 4096;
        for _ in 0..8 {
            let mut pids = vec![0i32; capacity];
            // macOS sys/proc_info.h: PROC_UID_ONLY = 4. Unlike
            // proc_listallpids, proc_listpids returns bytes, not a PID count.
            const PROC_UID_ONLY: u32 = 4;
            let bytes = unsafe {
                libc::proc_listpids(
                    PROC_UID_ONLY,
                    libc::geteuid(),
                    pids.as_mut_ptr() as *mut _,
                    (pids.len() * std::mem::size_of::<libc::pid_t>()) as i32,
                )
            };
            if bytes <= 0 || !(bytes as usize).is_multiple_of(std::mem::size_of::<libc::pid_t>()) {
                return Err(bad_inspection("current-UID process inventory failed"));
            }
            let count = bytes as usize / std::mem::size_of::<libc::pid_t>();
            if count < capacity {
                return Ok(pids
                    .into_iter()
                    .take(count)
                    .filter(|p| *p > 0)
                    .map(|p| p as u32)
                    .collect());
            }
            capacity *= 2;
        }
        Err(bad_inspection("process inventory remained truncated"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        fs::read_dir("/proc")?
            .filter_map(|entry| match entry {
                Ok(entry) => entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    .map(Ok),
                Err(e) => Some(Err(e)),
            })
            .collect()
    }
}

fn discover_imports(
    ownership: &mut HandoffOwnership,
    deadline: Instant,
) -> std::io::Result<Vec<TestProcessIdentity>> {
    #[cfg(test)]
    if ownership.inspection_failure {
        return Err(bad_inspection("injected fixture inspection failure"));
    }
    let mut found = Vec::new();
    for pid in all_process_pids()? {
        if Instant::now() >= deadline {
            return Err(bad_inspection("fixture inventory deadline exceeded"));
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            match fs::metadata(format!("/proc/{pid}")) {
                Ok(metadata) if metadata.uid() != unsafe { libc::geteuid() } => continue,
                Ok(_) => {}
                Err(_) if test_process_birth(pid)?.is_none() => continue,
                Err(error) => return Err(error),
            }
        }
        // A fixture cannot own a process born before the test process that
        // exclusively created it. This excludes pre-existing user processes
        // before probing their executable, even if proc_pidpath is unavailable.
        let Some(birth) = test_process_birth(pid).map_err(|error| {
            bad_inspection(&format!("process birth inventory PID {pid}: {error}"))
        })?
        else {
            continue;
        };
        if birth < ownership.owner_birth {
            continue;
        }
        // Inspect argv only after the kernel executable matches our Cargo binary.
        let inspected = process_executable(pid);
        #[cfg(test)]
        let inspected = match ownership.executable_failure {
            Some((target, error)) if target == pid => Err(std::io::Error::from_raw_os_error(error)),
            _ => inspected,
        };
        let Some(executable) = resolve_identity_inspection(
            pid,
            birth,
            "executable inventory",
            inspected,
            test_process_birth,
        )?
        else {
            continue;
        };
        if !is_test_herdr_binary(&executable) {
            continue;
        }
        let result: std::io::Result<Option<TestProcessIdentity>> = (|| {
            let Some(mut identity) = test_process_identity(pid)? else {
                return Ok(None);
            };
            if identity.birth != birth || !is_test_herdr_binary(&identity.executable) {
                return Ok(None);
            }
            let args = handoff_argv(pid)?;
            if test_process_birth(pid)? != Some(birth) {
                return Ok(None);
            }
            identity.import_socket = exact_import_socket(&args, &ownership.data_dirs);
            Ok(identity.import_socket.is_some().then_some(identity))
        })();
        if let Some(identity) = resolve_identity_inspection(
            pid,
            birth,
            "import identity/argv inventory",
            result,
            test_process_birth,
        )?
        .flatten()
        {
            write_fixture_ledger(
                    serde_json::json!({"pid": identity.pid, "birth": identity.birth, "executable": identity.executable, "kind": "import", "socket": identity.import_socket}),
                ).map_err(|error| bad_inspection(&format!(
                    "import ledger PID {pid} birth {birth:?}: {error}"
                )))?;
            if !ownership.imports.contains(&identity) {
                ownership.imports.push(identity.clone());
            }
            found.push(identity);
        }
    }
    Ok(found)
}

pub fn handoff_replacement_pids(runtime_dir: &Path) -> std::io::Result<Vec<u32>> {
    let state = fixture_registry()
        .get(
            runtime_dir
                .parent()
                .ok_or_else(|| bad_inspection("runtime parent missing"))?,
        )
        .cloned()
        .ok_or_else(|| bad_inspection("unregistered handoff fixture"))?;
    let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
    Ok(
        discover_imports(&mut guard, Instant::now() + Duration::from_secs(2))?
            .into_iter()
            .map(|p| p.pid)
            .collect(),
    )
}

fn same_process(expected: &TestProcessIdentity, current: Option<&TestProcessIdentity>) -> bool {
    current.is_some_and(|current| {
        expected.pid > 0
            && current.pid == expected.pid
            && current.birth == expected.birth
            && current.executable == expected.executable
    })
}

fn identity_still_owned(identity: &TestProcessIdentity) -> std::io::Result<bool> {
    identity_still_owned_from(
        identity,
        test_process_identity,
        test_process_birth,
        process_runtime_dir,
        read_cmdline,
        handoff_argv,
    )
}

fn identity_still_owned_from(
    identity: &TestProcessIdentity,
    mut read_identity: impl FnMut(u32) -> std::io::Result<Option<TestProcessIdentity>>,
    read_birth: impl FnMut(u32) -> std::io::Result<Option<(u64, u64)>>,
    mut read_runtime: impl FnMut(u32) -> std::io::Result<Option<PathBuf>>,
    mut read_server_args: impl FnMut(u32) -> std::io::Result<Vec<String>>,
    mut read_import_args: impl FnMut(u32) -> std::io::Result<Vec<String>>,
) -> std::io::Result<bool> {
    let mut operation = "initial identity";
    let result = (|| {
        let Some(current) = read_identity(identity.pid)? else {
            return Ok(false);
        };
        if !same_process(identity, Some(&current)) {
            return Ok(false);
        }
        if let Some(runtime) = &identity.runtime_dir {
            operation = "runtime environment";
            if read_runtime(identity.pid)?.as_ref() != Some(runtime) {
                return Ok(false);
            }
            operation = "server argv";
            if !read_server_args(identity.pid)?
                .iter()
                .any(|arg| arg == "server")
            {
                return Ok(false);
            }
        }
        if let Some(socket) = &identity.import_socket {
            operation = "import argv";
            let args = read_import_args(identity.pid)?;
            let dirs = HashSet::from([socket.parent().unwrap().to_path_buf()]);
            if exact_import_socket(&args, &dirs).as_ref() != Some(socket) {
                return Ok(false);
            }
        }
        operation = "final identity";
        Ok(same_process(
            identity,
            read_identity(identity.pid)?.as_ref(),
        ))
    })();
    match resolve_identity_inspection(identity.pid, identity.birth, operation, result, read_birth)?
    {
        Some(owned) => Ok(owned),
        None => Ok(false),
    }
}

pub fn terminate_test_process(
    identity: &TestProcessIdentity,
    deadline: Instant,
) -> std::io::Result<()> {
    for (signal, grace) in [
        (libc::SIGTERM, Duration::from_millis(400)),
        (libc::SIGKILL, Duration::from_secs(2)),
    ] {
        // Never signal a reused PID, a changed executable, or a changed import.
        if identity_still_owned(identity)?
            && unsafe { libc::kill(identity.pid as i32, signal) } != 0
        {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ESRCH) {
                return Err(bad_inspection(&format!(
                    "signal {signal} PID {} birth {:?}: {e}",
                    identity.pid, identity.birth
                )));
            }
        }
        let end = deadline.min(Instant::now() + grace);
        loop {
            let mut status = 0;
            unsafe {
                libc::waitpid(identity.pid as i32, &mut status, libc::WNOHANG);
            }
            if !identity_still_owned(identity)? {
                return Ok(());
            }
            if Instant::now() >= end {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    Err(bad_inspection(&format!(
        "owned PID {} birth {:?} survived bounded cleanup",
        identity.pid, identity.birth
    )))
}

fn finish_handoff_fixture(state: &FixtureState) -> std::io::Result<()> {
    let mut ownership = state.lock().unwrap_or_else(|e| e.into_inner());
    if ownership.finished {
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut journal_error = None;
    match fs::read_to_string(ownership.base.join("producers.jsonl")) {
        Ok(journal) => {
            for line in journal.lines() {
                let record = (|| -> std::io::Result<TestProcessIdentity> {
                    let value: serde_json::Value = serde_json::from_str(line)?;
                    let pid: u32 = serde_json::from_value(value["pid"].clone())?;
                    let birth: (u64, u64) = serde_json::from_value(value["birth"].clone())?;
                    let executable: PathBuf = serde_json::from_value(value["executable"].clone())?;
                    if pid == 0
                        || pid > i32::MAX as u32
                        || !is_test_herdr_binary(&executable)
                        || birth < ownership.owner_birth
                    {
                        return Err(bad_inspection("invalid parent-owned producer record"));
                    }
                    Ok(TestProcessIdentity {
                        pid,
                        birth,
                        executable,
                        import_socket: None,
                        runtime_dir: None,
                    })
                })();
                match record {
                    Ok(identity) if !ownership.producers.contains(&identity) => {
                        ownership.producers.push(identity)
                    }
                    Ok(_) => {}
                    Err(error) => {
                        journal_error = Some(bad_inspection(&format!("producer journal: {error}")))
                    }
                }
            }
            if !journal.is_empty() && !journal.ends_with('\n') {
                journal_error = Some(bad_inspection("incomplete producer journal"));
            }
        }
        Err(error) => journal_error = Some(bad_inspection(&format!("producer journal: {error}"))),
    }
    if ownership
        .base
        .join("pending-startup")
        .try_exists()
        .map_err(|error| bad_inspection(&format!("pending-startup marker: {error}")))?
    {
        journal_error = Some(bad_inspection(
            "nested child startup ownership is incomplete",
        ));
    }
    for producer in ownership.producers.clone() {
        if identity_still_owned(&producer)
            .map_err(|error| bad_inspection(&format!("producer inspection: {error}")))?
        {
            ownership.terminated_servers += 1;
        }
        terminate_test_process(&producer, deadline)
            .map_err(|error| bad_inspection(&format!("producer cleanup: {error}")))?;
        unregister_spawned_herdr_pid(Some(producer.pid));
    }
    for import in ownership.imports.clone() {
        if identity_still_owned(&import)
            .map_err(|error| bad_inspection(&format!("recorded import inspection: {error}")))?
        {
            ownership.terminated_servers += 1;
        }
        terminate_test_process(&import, deadline)
            .map_err(|error| bad_inspection(&format!("recorded import cleanup: {error}")))?;
    }
    if ownership.starting {
        return Err(bad_inspection("fixture still owns pending startup"));
    }
    if let Some(failure) = &ownership.unresolved_startup {
        journal_error = Some(bad_inspection(failure));
    }
    let mut empty_scans = 0;
    while Instant::now() < deadline {
        let imports = discover_imports(&mut ownership, deadline)?;
        if imports.is_empty() {
            empty_scans += 1;
            if empty_scans == 2 {
                if let Some(error) = journal_error {
                    return Err(error);
                }
                if !ownership.borrowed {
                    fs::remove_dir_all(&ownership.base)
                        .map_err(|error| bad_inspection(&format!("fixture removal: {error}")))?;
                }
                unregister_runtime_dir(&ownership.base.join("runtime"));
                fixture_registry().remove(&ownership.base);
                ownership.finished = true;
                return Ok(());
            }
        } else {
            empty_scans = 0;
            for import in imports {
                if identity_still_owned(&import).map_err(|error| {
                    bad_inspection(&format!("discovered import inspection: {error}"))
                })? {
                    ownership.terminated_servers += 1;
                }
                terminate_test_process(&import, deadline).map_err(|error| {
                    bad_inspection(&format!("discovered import cleanup: {error}"))
                })?;
            }
        }
        thread::sleep(Duration::from_millis(40));
    }
    Err(bad_inspection(
        "fixture did not reach quiescence before cleanup deadline",
    ))
}

pub fn register_spawned_herdr_pid(pid: Option<u32>) {
    let Some(pid) = pid else {
        return;
    };

    ensure_cleanup_hooks();
    if let Some(identity) = settled_herdr_identity(pid).expect("inspect registered direct child") {
        write_fixture_ledger(serde_json::json!({"pid": pid, "birth": identity.birth, "executable": identity.executable})).expect("record direct child");
        pid_registry_lock().insert(pid, identity);
    }
}

pub fn unregister_spawned_herdr_pid(pid: Option<u32>) {
    let Some(pid) = pid else {
        return;
    };

    if let Some(registry) = PID_REGISTRY.get() {
        let mut guard = registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.remove(&pid);
    }
}

pub fn register_runtime_dir(path: &Path) {
    ensure_cleanup_hooks();

    let _ = fs::create_dir_all(path);
    let _ = fs::write(
        path.join(RUNTIME_OWNER_MARKER),
        std::process::id().to_string(),
    );

    let mut runtime_dirs = runtime_dir_registry_lock();
    runtime_dirs.insert(path.to_path_buf());
}

pub fn unregister_runtime_dir(path: &Path) {
    if let Some(registry) = RUNTIME_DIR_REGISTRY.get() {
        let mut guard = registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.remove(path);
    }
}

#[cfg(target_os = "linux")]
pub fn herdr_server_pids_for_runtime_dir(runtime_dir: &Path) -> std::io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for identity in runtime_server_identities()? {
        if identity.runtime_dir.as_deref() == Some(runtime_dir) {
            pids.push(identity.pid);
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

pub fn cleanup_test_base(base: &Path) {
    let fixture = fixture_registry().get(base).cloned();
    if let Some(fixture) = fixture {
        finish_handoff_fixture(&fixture).expect("handoff fixture cleanup");
        return;
    }
    let runtime_dir = base.join("runtime");
    let runtime_dirs = HashSet::from([runtime_dir.clone()]);

    terminate_servers_for_runtime_dirs(&runtime_dirs);
    unregister_runtime_dir(&runtime_dir);
    let _ = fs::remove_dir_all(base);
}

pub fn wait_for_socket(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() && UnixStream::connect(path).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("socket did not appear at {}", path.display());
}

pub fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("file did not appear at {}", path.display());
}

fn encode_varint_u32(v: u32) -> Vec<u8> {
    if v < 251 {
        vec![v as u8]
    } else if v < 65536 {
        let mut buf = vec![251u8];
        buf.extend_from_slice(&(v as u16).to_le_bytes());
        buf
    } else {
        let mut buf = vec![252u8];
        buf.extend_from_slice(&v.to_le_bytes());
        buf
    }
}

fn encode_varint_u16(v: u16) -> Vec<u8> {
    if v < 251 {
        vec![v as u8]
    } else {
        let mut buf = vec![251u8];
        buf.extend_from_slice(&v.to_le_bytes());
        buf
    }
}

fn frame_message(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut framed = len.to_le_bytes().to_vec();
    framed.extend_from_slice(payload);
    framed
}

fn decode_varint_u32(payload: &[u8], offset: usize) -> Result<(u32, usize), String> {
    if offset >= payload.len() {
        return Err("payload too short for varint".into());
    }
    let first_byte = payload[offset];
    match first_byte {
        0..=250 => Ok((first_byte as u32, 1)),
        251 => {
            if offset + 3 > payload.len() {
                return Err("payload too short for u16 varint".into());
            }
            let v = u16::from_le_bytes(
                payload[offset + 1..offset + 3]
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| e.to_string())?,
            );
            Ok((v as u32, 3))
        }
        252 => {
            if offset + 5 > payload.len() {
                return Err("payload too short for u32 varint".into());
            }
            let v = u32::from_le_bytes(
                payload[offset + 1..offset + 5]
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| e.to_string())?,
            );
            Ok((v, 5))
        }
        _ => Err(format!("unsupported varint tag: {first_byte}")),
    }
}

fn encode_varint_enum(variant_idx: u32, fields: &[&[u8]]) -> Vec<u8> {
    let mut buf = encode_varint_u32(variant_idx);
    for field in fields {
        buf.extend_from_slice(field);
    }
    buf
}

fn encode_string(value: &str) -> Vec<u8> {
    let mut encoded = encode_varint_u32(value.len() as u32);
    encoded.extend_from_slice(value.as_bytes());
    encoded
}

fn decode_string(payload: &[u8], offset: &mut usize) -> Result<String, String> {
    let (len, consumed) = decode_varint_u32(payload, *offset)?;
    *offset += consumed;
    let len = len as usize;
    if *offset + len > payload.len() {
        return Err("payload too short for string content".into());
    }
    let value = String::from_utf8(payload[*offset..*offset + len].to_vec())
        .map_err(|err| err.to_string())?;
    *offset += len;
    Ok(value)
}

fn decode_welcome(payload: &[u8]) -> Result<(u32, Option<String>), String> {
    let mut offset = 0;
    let (variant, consumed) = decode_varint_u32(payload, offset)?;
    offset += consumed;
    if variant != 0 {
        return Err(format!(
            "expected Welcome (variant 0), got variant {variant}"
        ));
    }

    let (version, consumed) = decode_varint_u32(payload, offset)?;
    offset += consumed;

    let (_encoding, consumed) = decode_varint_u32(payload, offset)?;
    offset += consumed;

    if offset >= payload.len() {
        return Err("payload too short for Option tag".into());
    }
    let option_tag = payload[offset];
    offset += 1;

    let error = if option_tag == 1 {
        let (str_len, consumed) = decode_varint_u32(payload, offset)?;
        offset += consumed;
        let str_len = str_len as usize;
        if offset + str_len > payload.len() {
            return Err("payload too short for string content".into());
        }
        Some(
            String::from_utf8(payload[offset..offset + str_len].to_vec())
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };

    Ok((version, error))
}

fn read_handshake_response(
    stream: &mut UnixStream,
    hello_payload: &[u8],
) -> Result<Vec<u8>, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&frame_message(hello_payload))
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 2 * 1024 * 1024 {
        return Err(format!("oversized response: {len}"));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).map_err(|e| e.to_string())?;
    Ok(payload)
}

pub fn client_handshake(
    stream: &mut UnixStream,
    version: u32,
    cols: u16,
    rows: u16,
) -> Result<(u32, Option<String>), String> {
    let hello_payload = encode_varint_enum(
        0,
        &[
            &encode_varint_u32(version),
            &encode_varint_u16(cols),
            &encode_varint_u16(rows),
            &encode_varint_u32(8),  // cell_width_px
            &encode_varint_u32(16), // cell_height_px
            &[0],                   // pixel_mouse = false
        ],
    );
    let response = read_handshake_response(stream, &hello_payload)?;
    decode_welcome(&response)
}

pub fn client_shell_handshake(
    stream: &mut UnixStream,
    endpoint_generation: u32,
    surface_cols: u16,
    surface_rows: u16,
) -> Result<(u32, Option<String>), String> {
    let data = serde_json::json!({
        "generation": endpoint_generation,
        "cell_width_px": 8,
        "cell_height_px": 16,
        "surface_size": {"cols": surface_cols, "rows": surface_rows},
        "pixel_mouse": false,
        "direct_graphics": false,
        "endpoint_keybindings": false,
        "mouse_capture": false,
        "snapshot_codecs": ["shell.snapshot.v1"],
        "surface_codecs": ["shell.surface.v1"],
        "input_codecs": ["shell.input.semantic.v1"],
        "blob_codecs": ["shell.blob.v1"]
    })
    .to_string();
    let hello_payload = encode_varint_enum(
        CLIENT_MESSAGE_ENDPOINT_CONTROL,
        &[&encode_string("endpoint.hello.v1"), &encode_string(&data)],
    );
    let response = read_handshake_response(stream, &hello_payload)?;
    let mut offset = 0;
    let (variant, consumed) = decode_varint_u32(&response, offset)?;
    offset += consumed;
    if variant != SERVER_MESSAGE_ENDPOINT_CONTROL {
        return Err(format!(
            "expected EndpointControl (variant {SERVER_MESSAGE_ENDPOINT_CONTROL}), got variant {variant}"
        ));
    }
    let kind = decode_string(&response, &mut offset)?;
    if kind != "endpoint.welcome.v1" {
        return Err(format!("expected endpoint.welcome.v1, got {kind}"));
    }
    let data = decode_string(&response, &mut offset)?;
    let value: serde_json::Value = serde_json::from_str(&data).map_err(|err| err.to_string())?;
    let generation = value["generation"]
        .as_u64()
        .ok_or_else(|| "endpoint welcome omitted generation".to_owned())?
        as u32;
    let error = value["error"]
        .as_object()
        .and_then(|error| error.get("message"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Ok((generation, error))
}

pub fn read_server_message(stream: &mut UnixStream) -> Result<(u32, Vec<u8>), String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read length prefix: {e}"))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 2 * 1024 * 1024 {
        return Err(format!("oversized frame: {len} bytes"));
    }
    if len == 0 {
        return Err("zero-length frame".into());
    }

    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|e| format!("read payload: {e}"))?;

    let (variant, consumed) = decode_varint_u32(&payload, 0)?;
    Ok((variant, payload[consumed..].to_vec()))
}

pub fn send_client_shell_shift_enter(stream: &mut UnixStream, pane_id: &str) -> Result<(), String> {
    let mut payload = encode_varint_u32(CLIENT_MESSAGE_CLIENT_SHELL_PANE_INPUT);
    payload.extend_from_slice(&encode_varint_u32(pane_id.len() as u32));
    payload.extend_from_slice(pane_id.as_bytes());
    payload.extend_from_slice(&encode_varint_u32(1)); // one pane input event
    payload.extend_from_slice(&encode_varint_u32(0)); // Key
    payload.extend_from_slice(&encode_varint_u32(1)); // Enter
    payload.push(1); // Shift
    payload.extend_from_slice(&encode_varint_u32(0)); // Press
    payload.extend_from_slice(&encode_varint_u16(1));
    payload.push(0); // no shifted codepoint
    payload.push(0); // no generated text
    payload.push(0); // does not track release
    payload.push(0); // no physical key id
    payload.push(0); // no Windows key record

    stream
        .write_all(&frame_message(&payload))
        .map_err(|e| format!("write client shell key: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("flush client shell key: {e}"))
}

pub fn send_client_shell_focus(stream: &mut UnixStream, focused: bool) -> Result<(), String> {
    let mut payload = encode_varint_u32(CLIENT_MESSAGE_CLIENT_SHELL_FOCUS);
    payload.push(u8::from(focused));
    stream
        .write_all(&frame_message(&payload))
        .map_err(|e| format!("write client shell focus: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("flush client shell focus: {e}"))
}

pub fn send_detach(stream: &mut UnixStream) -> Result<(), String> {
    let detach_payload = encode_varint_u32(4);
    let framed = frame_message(&detach_payload);
    stream
        .write_all(&framed)
        .map_err(|e| format!("write detach: {e}"))?;
    stream.flush().map_err(|e| format!("flush detach: {e}"))?;
    Ok(())
}

pub fn drain_messages(stream: &mut UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    while read_server_message(stream).is_ok() {}
    stream.set_read_timeout(None).unwrap();
}

pub fn wait_until<F>(timeout: Duration, interval: Duration, mut predicate: F) -> bool
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        thread::sleep(interval);
    }
    predicate()
}

pub fn wait_for_message_variant(
    stream: &mut UnixStream,
    timeout: Duration,
    variant: u32,
) -> Result<bool, String> {
    wait_for_message_variants(stream, timeout, &[variant])
}

pub fn wait_for_message_variants(
    stream: &mut UnixStream,
    timeout: Duration,
    variants: &[u32],
) -> Result<bool, String> {
    let read_timeout = Some(Duration::from_millis(200));
    // Darwin can reject resetting the timeout after peer closure with queued data.
    if stream.read_timeout().map_err(|e| e.to_string())? != read_timeout {
        stream
            .set_read_timeout(read_timeout)
            .map_err(|e| e.to_string())?;
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match read_server_message(stream) {
            Ok((got, _)) if variants.contains(&got) => return Ok(true),
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
    Ok(false)
}

pub fn wait_for_client_shell_bootstrap(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + timeout;
    let mut saw_snapshot = false;
    while Instant::now() < deadline {
        match read_server_message(stream) {
            Ok((SERVER_MESSAGE_ENDPOINT_CONTROL, payload)) => {
                let mut offset = 0;
                if decode_string(&payload, &mut offset).as_deref() == Ok("shell.snapshot.v1") {
                    saw_snapshot = true;
                }
            }
            Ok((SERVER_MESSAGE_PANE_SURFACE, _)) if saw_snapshot => return Ok(()),
            Ok((SERVER_MESSAGE_PANE_SURFACE, _)) => {
                return Err("client shell pane surface arrived before its snapshot".into());
            }
            Ok(_) | Err(_) => {}
        }
    }
    Err(format!(
        "timed out waiting for client shell {}",
        if saw_snapshot {
            "pane surface"
        } else {
            "snapshot"
        }
    ))
}

pub fn wait_for_disconnect(stream: &mut UnixStream, timeout: Duration) -> Result<bool, String> {
    stream.set_nonblocking(true).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + timeout;
    let mut idle_since = None;
    let result = loop {
        match read_server_message(stream) {
            Ok(_) => idle_since = None,
            Err(err)
                if err.to_ascii_lowercase().contains("would block")
                    || err.contains("Resource temporarily unavailable") =>
            {
                let idle_started = *idle_since.get_or_insert_with(Instant::now);
                if idle_started.elapsed() >= Duration::from_millis(200) {
                    break Ok(true);
                }
            }
            Err(_) => break Ok(true),
        }
        if Instant::now() >= deadline {
            break Ok(false);
        }
        thread::sleep(Duration::from_millis(25));
    };
    let _ = stream.set_nonblocking(false);
    result
}

pub fn cleanup_registered_herdr_pids() {
    let fixtures: Vec<_> = fixture_registry().values().cloned().collect();
    for fixture in fixtures {
        if let Err(error) = finish_handoff_fixture(&fixture) {
            eprintln!("registered handoff fixture cleanup unresolved: {error}");
        }
    }
    let identities: Vec<_> = pid_registry_lock().values().cloned().collect();
    for identity in identities {
        match terminate_test_process(&identity, Instant::now() + Duration::from_millis(2400)) {
            Ok(()) => unregister_spawned_herdr_pid(Some(identity.pid)),
            Err(error) => eprintln!(
                "registered PID {} cleanup unresolved: {error}",
                identity.pid
            ),
        }
    }
    let runtime_dirs = registered_runtime_dirs_snapshot();
    terminate_servers_for_runtime_dirs(&runtime_dirs);

    let _ = cleanup_servers_with_missing_runtime_dir();
}

fn ensure_cleanup_hooks() {
    INIT.call_once(|| {
        let _ = cleanup_servers_with_missing_runtime_dir();
        start_global_watchdog();

        let _ = CLEANUP_GUARD.set(CleanupGuard);

        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            cleanup_registered_herdr_pids();
            previous_hook(panic_info);
        }));

        let _ = ctrlc::set_handler(|| {
            cleanup_registered_herdr_pids();
            std::process::exit(130);
        });

        unsafe {
            libc::atexit(run_atexit_cleanup);
        }
    });
}

fn pid_registry_lock(
) -> std::sync::MutexGuard<'static, std::collections::HashMap<u32, TestProcessIdentity>> {
    PID_REGISTRY
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn runtime_dir_registry_lock() -> std::sync::MutexGuard<'static, HashSet<PathBuf>> {
    RUNTIME_DIR_REGISTRY
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn registered_runtime_dirs_snapshot() -> HashSet<PathBuf> {
    if let Some(runtime_dirs) = RUNTIME_DIR_REGISTRY.get() {
        runtime_dirs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    } else {
        HashSet::new()
    }
}

fn should_terminate_runtime_dir(
    runtime_dir: &Path,
    registered_runtime_dirs: &HashSet<PathBuf>,
) -> bool {
    if !registered_runtime_dirs.contains(runtime_dir) {
        return false;
    }

    if !runtime_dir.exists() {
        return true;
    }

    !runtime_dir_owner_alive(runtime_dir)
}

fn start_global_watchdog() {
    thread::spawn(|| loop {
        thread::sleep(WATCHDOG_SCAN_INTERVAL);

        if let Err(err) = cleanup_servers_with_missing_runtime_dir() {
            eprintln!("herdr test cleanup watchdog error: {err}");
        }
    });
}

fn guarded_handoff_runtime(runtime: &Path) -> bool {
    fixture_registry().contains_key(runtime.parent().unwrap_or(runtime))
}

fn cleanup_servers_with_missing_runtime_dir() -> std::io::Result<()> {
    let registered_runtime_dirs = registered_runtime_dirs_snapshot();
    if registered_runtime_dirs.is_empty() {
        return Ok(());
    }

    for identity in runtime_server_identities()? {
        let runtime = identity
            .runtime_dir
            .as_ref()
            .expect("runtime-bound discovery");
        if !guarded_handoff_runtime(runtime)
            && should_terminate_runtime_dir(runtime, &registered_runtime_dirs)
        {
            terminate_test_process(&identity, Instant::now() + Duration::from_millis(2400))?;
        }
    }
    Ok(())
}

fn terminate_servers_for_runtime_dirs(runtime_dirs: &HashSet<PathBuf>) {
    if runtime_dirs.is_empty() {
        return;
    }
    let identities = match runtime_server_identities() {
        Ok(identities) => identities,
        Err(error) => {
            eprintln!("runtime inventory unresolved: {error}");
            return;
        }
    };
    for identity in identities {
        let runtime = identity
            .runtime_dir
            .as_ref()
            .expect("runtime-bound discovery");
        if !guarded_handoff_runtime(runtime) && runtime_dirs.contains(runtime) {
            if let Err(error) =
                terminate_test_process(&identity, Instant::now() + Duration::from_millis(2400))
            {
                eprintln!(
                    "runtime-owned PID {} cleanup unresolved: {error}",
                    identity.pid
                );
            }
        }
    }
}

// Capture birth/executable BEFORE reading ownership. Never reconstruct the
// expected identity from a bare PID after the runtime/argv checks.
fn runtime_identity_from(
    pid: u32,
    mut inspect: impl FnMut(u32) -> std::io::Result<Option<TestProcessIdentity>>,
    mut ownership: impl FnMut(u32) -> std::io::Result<Option<PathBuf>>,
) -> std::io::Result<Option<TestProcessIdentity>> {
    let Some(mut identity) = inspect(pid)? else {
        return Ok(None);
    };
    if !is_test_herdr_binary(&identity.executable) {
        return Ok(None);
    }
    let Some(runtime) = ownership(pid)? else {
        return Ok(None);
    };
    if !same_process(&identity, inspect(pid)?.as_ref()) {
        return Ok(None);
    }
    identity.runtime_dir = Some(runtime);
    Ok(Some(identity))
}

fn runtime_server_identities() -> std::io::Result<Vec<TestProcessIdentity>> {
    let proc_entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut identities = Vec::new();
    for entry in proc_entries {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            match entry.metadata() {
                Ok(metadata) if metadata.uid() != unsafe { libc::geteuid() } => continue,
                Ok(_) => {}
                Err(_) if test_process_birth(pid)?.is_none() => continue,
                Err(error) => return Err(error),
            }
        }
        let result = runtime_identity_from(pid, test_process_identity, |pid| {
            if !read_cmdline(pid)?.iter().any(|arg| arg == "server") {
                return Ok(None);
            }
            process_runtime_dir(pid)
        });
        match result {
            Ok(Some(identity)) => identities.push(identity),
            Ok(None) => {}
            Err(_) if test_process_birth(pid)?.is_none() => {}
            Err(error) => return Err(error),
        }
    }
    Ok(identities)
}

fn read_cmdline(pid: u32) -> std::io::Result<Vec<String>> {
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))?;
    Ok(cmdline
        .split(|byte| *byte == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect())
}

fn process_runtime_dir(pid: u32) -> std::io::Result<Option<PathBuf>> {
    let environ = fs::read(format!("/proc/{pid}/environ"))?;

    let mut socket_path: Option<PathBuf> = None;

    for entry in environ.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }

        let kv = String::from_utf8_lossy(entry);
        if let Some(value) = kv.strip_prefix("XDG_RUNTIME_DIR=") {
            return Ok(Some(PathBuf::from(value)));
        }

        if let Some(value) = kv.strip_prefix("HERDR_SOCKET_PATH=") {
            socket_path = Some(PathBuf::from(value));
        }
    }

    Ok(socket_path.and_then(|path| path.parent().map(Path::to_path_buf)))
}

fn runtime_dir_owner_alive(runtime_dir: &Path) -> bool {
    let marker = runtime_dir.join(RUNTIME_OWNER_MARKER);
    let Ok(contents) = fs::read_to_string(marker) else {
        return false;
    };

    let Ok(owner_pid) = contents.trim().parse::<libc::pid_t>() else {
        return false;
    };

    process_exists(owner_pid)
}

fn is_test_herdr_binary(path: &Path) -> bool {
    // /proc resolves executable symlinks. Match only this Cargo build, including
    // custom target directories; binary identity alone never grants ownership.
    static TEST_BINARY: OnceLock<Option<PathBuf>> = OnceLock::new();
    TEST_BINARY
        .get_or_init(|| fs::canonicalize(env!("CARGO_BIN_EXE_herdr")).ok())
        .as_deref()
        .is_some_and(|binary| path == binary)
}

extern "C" fn run_atexit_cleanup() {
    cleanup_registered_herdr_pids();
}

struct CleanupGuard;

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        cleanup_registered_herdr_pids();
    }
}

fn process_exists(pid: libc::pid_t) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        true
    } else {
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_ownership_rejects_wrong_paths_and_malformed_arguments() {
        let dirs = HashSet::from([PathBuf::from("/owned/config/herdr-dev/sessions/work")]);
        let valid = vec![
            "/cargo/herdr".to_string(),
            "server".into(),
            "--handoff-import".into(),
            "/owned/config/herdr-dev/sessions/work/herdr-handoff-12.sock".into(),
            "unused-token".into(),
        ];
        assert!(exact_import_socket(&valid, &dirs).is_some());
        for socket in [
            "herdr-handoff-12.sock",
            "/another/config/herdr-dev/sessions/work/herdr-handoff-12.sock",
            "/owned/config/herdr-dev/sessions/other/herdr-handoff-12.sock",
            "/owned/config/herdr-dev/sessions/work-extra/herdr-handoff-12.sock",
            "/owned/config/herdr-dev/sessions/work/../work/herdr-handoff-12.sock",
            "/owned/config/herdr-dev/sessions/work/./herdr-handoff-12.sock",
            "/owned/config/herdr-dev/sessions/work/herdr-handoff-0.sock",
            "/owned/config/herdr-dev/sessions/work/herdr-handoff-x.sock",
        ] {
            let mut args = valid.clone();
            args[3] = socket.into();
            assert!(
                exact_import_socket(&args, &dirs).is_none(),
                "accepted {socket}"
            );
        }
        let mut args = valid.clone();
        args.remove(1);
        assert!(exact_import_socket(&args, &dirs).is_none());
        let mut args = valid;
        args.push("extra".into());
        assert!(exact_import_socket(&args, &dirs).is_none());
    }

    #[test]
    fn handoff_identity_rejects_reuse_wrong_executable_and_missing_metadata() {
        let expected = TestProcessIdentity {
            pid: 42,
            birth: (123, 4),
            executable: "/cargo/herdr".into(),
            import_socket: None,
            runtime_dir: None,
        };
        assert!(same_process(&expected, Some(&expected)));
        assert!(!same_process(&expected, None));
        let mut reused = expected.clone();
        reused.birth.0 += 1;
        assert!(!same_process(&expected, Some(&reused)));
        let mut wrong_exe = expected.clone();
        wrong_exe.executable = "/installed/herdr".into();
        assert!(!same_process(&expected, Some(&wrong_exe)));
        assert!(!is_test_herdr_binary(Path::new("/installed/herdr")));
    }

    fn inspection_identity() -> TestProcessIdentity {
        TestProcessIdentity {
            pid: 42,
            birth: (123, 4),
            executable: "/cargo/herdr".into(),
            import_socket: Some("/owned/data/herdr-handoff-12.sock".into()),
            runtime_dir: None,
        }
    }

    #[test]
    fn ownership_inspection_exit_during_import_argv() {
        let expected = inspection_identity();
        for birth in [None, Some((124, 4))] {
            let result = identity_still_owned_from(
                &expected,
                |_| Ok(Some(expected.clone())),
                |_| Ok(birth),
                |_| panic!("unexpected runtime read"),
                |_| panic!("unexpected server argv read"),
                |_| Err(std::io::Error::from_raw_os_error(libc::ESRCH)),
            );
            assert!(
                !result.unwrap(),
                "gone identity must not authorize signaling"
            );
        }
    }

    #[test]
    fn ownership_inspection_failed_executable_changed_birth() {
        let mut births = [Some((123, 4)), Some((124, 4))].into_iter();
        assert!(test_process_identity_from(
            42,
            |_| Ok(births.next().unwrap()),
            |_| Err(std::io::Error::from_raw_os_error(libc::ESRCH)),
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn ownership_inspection_errors_require_positive_disappearance() {
        let mut expected = inspection_identity();
        expected.runtime_dir = Some("/owned/runtime".into());
        for operation in [
            "initial identity",
            "runtime environment",
            "server argv",
            "import argv",
            "final identity",
        ] {
            for errno in [
                libc::ESRCH,
                libc::ENOENT,
                libc::EPERM,
                libc::EACCES,
                libc::EIO,
                libc::EINVAL,
            ] {
                // Absent, replaced, still live, and uncertain kernel birth.
                for outcome in 0..4 {
                    let mut identity_reads = 0;
                    let result = identity_still_owned_from(
                        &expected,
                        |_| {
                            identity_reads += 1;
                            let probe = if identity_reads == 1 {
                                "initial identity"
                            } else {
                                "final identity"
                            };
                            if operation == probe {
                                Err(std::io::Error::from_raw_os_error(errno))
                            } else {
                                Ok(Some(expected.clone()))
                            }
                        },
                        |_| match outcome {
                            0 => Ok(None),
                            1 => Ok(Some((124, 4))),
                            2 => Ok(Some(expected.birth)),
                            _ => Err(std::io::Error::from_raw_os_error(libc::EPERM)),
                        },
                        |_| {
                            if operation == "runtime environment" {
                                Err(std::io::Error::from_raw_os_error(errno))
                            } else {
                                Ok(expected.runtime_dir.clone())
                            }
                        },
                        |_| {
                            if operation == "server argv" {
                                Err(std::io::Error::from_raw_os_error(errno))
                            } else {
                                Ok(vec!["server".into()])
                            }
                        },
                        |_| {
                            if operation == "import argv" {
                                Err(std::io::Error::from_raw_os_error(errno))
                            } else {
                                Ok(vec![
                                    "/cargo/herdr".into(),
                                    "server".into(),
                                    "--handoff-import".into(),
                                    expected
                                        .import_socket
                                        .as_ref()
                                        .unwrap()
                                        .display()
                                        .to_string(),
                                    "PRIVATE_TOKEN".into(),
                                ])
                            }
                        },
                    );
                    if outcome < 2 {
                        assert!(
                            !result.unwrap(),
                            "{operation}: gone process cannot authorize signaling"
                        );
                    } else {
                        let error = result.unwrap_err().to_string();
                        assert!(error.contains(operation), "{error}");
                        assert!(error.contains("PID 42 birth (123, 4)"), "{error}");
                        assert!(
                            error.contains(&std::io::Error::from_raw_os_error(errno).to_string()),
                            "{error}"
                        );
                        assert_eq!(
                            error.contains("birth recheck failed"),
                            outcome == 3,
                            "{error}"
                        );
                        assert!(!error.contains("PRIVATE_TOKEN"));
                        assert!(!error.contains("/owned/runtime"));
                    }
                }
            }
        }
        assert!(identity_still_owned_from(
            &expected,
            |_| Ok(Some(expected.clone())),
            |_| panic!("successful probes need no error recheck"),
            |_| Ok(expected.runtime_dir.clone()),
            |_| Ok(vec!["server".into()]),
            |_| Ok(vec![
                "/cargo/herdr".into(),
                "server".into(),
                "--handoff-import".into(),
                expected
                    .import_socket
                    .as_ref()
                    .unwrap()
                    .display()
                    .to_string(),
                "PRIVATE_TOKEN".into()
            ]),
        )
        .unwrap());
    }

    #[test]
    fn ownership_inspection_executable_errors_preserve_live_uncertainty() {
        for outcome in 0..4 {
            let mut reads = 0;
            let result = test_process_identity_from(
                42,
                |_| {
                    reads += 1;
                    if reads == 1 {
                        return Ok(Some((123, 4)));
                    }
                    match outcome {
                        0 => Ok(None),
                        1 => Ok(Some((124, 4))),
                        2 => Ok(Some((123, 4))),
                        _ => Err(std::io::Error::from_raw_os_error(libc::EPERM)),
                    }
                },
                |_| Err(std::io::Error::from_raw_os_error(libc::ESRCH)),
            );
            if outcome < 2 {
                assert!(result.unwrap().is_none());
            } else {
                let error = result.unwrap_err().to_string();
                assert!(
                    error.contains("identity executable PID 42 birth (123, 4)"),
                    "{error}"
                );
                assert!(error.contains(&std::io::Error::from_raw_os_error(libc::ESRCH).to_string()));
                assert_eq!(error.contains("birth recheck failed"), outcome == 3);
            }
        }
    }

    #[test]
    fn runtime_discovery_rejects_pid_reuse_during_ownership_read() {
        let expected = TestProcessIdentity {
            pid: 42,
            birth: (123, 4),
            executable: fs::canonicalize(env!("CARGO_BIN_EXE_herdr")).unwrap(),
            import_socket: None,
            runtime_dir: None,
        };
        let current = std::cell::RefCell::new(expected.clone());
        let result = runtime_identity_from(
            42,
            |_| Ok(Some(current.borrow().clone())),
            |_| {
                current.borrow_mut().birth.0 += 1;
                Ok(Some(PathBuf::from("/owned/runtime")))
            },
        )
        .unwrap();
        assert!(
            result.is_none(),
            "a reused PID must not become a signal target"
        );
        *current.borrow_mut() = expected.clone();
        let result = runtime_identity_from(
            42,
            |_| Ok(Some(current.borrow().clone())),
            |_| {
                current.borrow_mut().executable = PathBuf::from("/unrelated/program");
                Ok(Some(PathBuf::from("/owned/runtime")))
            },
        )
        .unwrap();
        assert!(result.is_none());
        let result = runtime_identity_from(
            42,
            |_| Ok(Some(expected.clone())),
            |_| Ok(Some(PathBuf::from("/owned/runtime"))),
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.birth, expected.birth);
        assert_eq!(
            result.runtime_dir.as_deref(),
            Some(Path::new("/owned/runtime"))
        );
    }

    #[test]
    fn handoff_procargs_decodes_only_argc_and_rejects_truncation() {
        let mut bytes = 2i32.to_ne_bytes().to_vec();
        bytes.extend_from_slice(
            b"/cargo/herdr\0\0/cargo/herdr\0server\0PRIVATE_ENV=must-not-decode\0",
        );
        assert_eq!(decode_procargs(&bytes).unwrap(), ["/cargo/herdr", "server"]);
        for bytes in [
            vec![],
            0i32.to_ne_bytes().to_vec(),
            (-1i32).to_ne_bytes().to_vec(),
            5000i32.to_ne_bytes().to_vec(),
            [
                2i32.to_ne_bytes().as_slice(),
                b"/cargo/herdr\0\0herdr\0unterminated",
            ]
            .concat(),
        ] {
            assert!(decode_procargs(&bytes).is_err());
        }
    }

    fn unique_missing_runtime_dir(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "herdr-watchdog-scoping-{label}-{}-{unique}",
            std::process::id()
        ))
    }

    #[test]
    fn watchdog_scoping_does_not_terminate_missing_unregistered_runtime_dir() {
        let runtime_dir = unique_missing_runtime_dir("unregistered");
        let registered_runtime_dirs = HashSet::new();

        assert!(
            !should_terminate_runtime_dir(&runtime_dir, &registered_runtime_dirs),
            "missing runtime dirs must not be killable until they are proven session-owned"
        );
    }

    #[test]
    fn watchdog_scoping_terminates_missing_registered_runtime_dir() {
        let runtime_dir = unique_missing_runtime_dir("registered");
        let mut registered_runtime_dirs = HashSet::new();
        registered_runtime_dirs.insert(runtime_dir.clone());

        assert!(
            should_terminate_runtime_dir(&runtime_dir, &registered_runtime_dirs),
            "missing runtime dirs that are session-owned should be considered killable"
        );
    }

    #[test]
    fn watchdog_scoping_preserves_registered_live_owner() {
        let runtime_dir = unique_missing_runtime_dir("live-owner");
        fs::create_dir_all(&runtime_dir).unwrap();
        fs::write(
            runtime_dir.join(RUNTIME_OWNER_MARKER),
            std::process::id().to_string(),
        )
        .unwrap();
        let registered_runtime_dirs = HashSet::from([runtime_dir.clone()]);
        let should_terminate = should_terminate_runtime_dir(&runtime_dir, &registered_runtime_dirs);
        fs::remove_dir_all(runtime_dir).unwrap();
        assert!(!should_terminate, "a live test owner must remain protected");
    }

    #[test]
    fn test_binary_matcher_accepts_cargo_test_binary() {
        let binary = std::fs::canonicalize(env!("CARGO_BIN_EXE_herdr"))
            .expect("Cargo-built binary must exist");
        assert!(
            is_test_herdr_binary(&binary),
            "Cargo-built binary should be considered test-owned regardless of target directory"
        );
    }

    #[test]
    fn test_binary_matcher_rejects_other_binaries() {
        let nested_build = Path::new(env!("CARGO_MANIFEST_DIR")).join("other/target/debug/herdr");
        let sibling_build = Path::new(env!("CARGO_BIN_EXE_herdr"))
            .parent()
            .unwrap()
            .join("other-build/herdr");
        for binary in [
            Path::new("/home/can/.local/bin/herdr"),
            Path::new("/tmp/other-checkout/target/debug/herdr"),
            nested_build.as_path(),
            sibling_build.as_path(),
        ] {
            assert!(
                !is_test_herdr_binary(binary),
                "other binaries must not be considered test-owned: {}",
                binary.display()
            );
        }
    }
}
