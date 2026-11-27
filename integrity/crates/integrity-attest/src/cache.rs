// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Stat-fingerprinted, TOCTOU-safe file cache with rate-limited diagnostics.

use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use yasvara_integrity_core::contract::MAX_KEYBOX_BYTES;

const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fingerprint {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    mode: u32,
    uid: u32,
    gid: u32,
}

impl Fingerprint {
    fn of(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
        }
    }
}

#[derive(Debug)]
pub enum Failure {
    Io { operation: &'static str, kind: io::ErrorKind, errno: Option<i32> },
    NotRegularFile,
    ChangedWhileReading,
    InvalidKeybox,
}

impl Failure {
    fn io(operation: &'static str, error: io::Error) -> Self {
        Self::Io { operation, kind: error.kind(), errno: error.raw_os_error() }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, kind, errno } => {
                write!(f, "{operation} failed (kind={kind:?}, errno={errno:?})")
            }
            Self::NotRegularFile => f.write_str("not a regular file"),
            Self::ChangedWhileReading => {
                f.write_str("file changed while loading; snapshot rejected")
            }
            Self::InvalidKeybox => f.write_str("invalid keybox or no usable supported key/chain"),
        }
    }
}

pub struct Lookup<'a, T> {
    pub entry: Option<&'a T>,
    pub loaded: bool,
    pub diagnostic: Option<Failure>,
}

pub struct FileCache<T> {
    fingerprint: Option<Fingerprint>,
    entry: Option<T>,
    retry_at: Option<Instant>,
    last_diagnostic: Option<Instant>,
}

impl<T> Default for FileCache<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> FileCache<T> {
    pub fn new() -> Self {
        Self { fingerprint: None, entry: None, retry_at: None, last_diagnostic: None }
    }

    pub fn current(
        &mut self,
        path: &Path,
        now: Instant,
        parse: impl FnOnce(&str) -> Option<T>,
    ) -> Lookup<'_, T> {
        self.current_with_reader(path, now, |s: String| parse(&s), read_snapshot)
    }

    pub fn current_bytes(
        &mut self,
        path: &Path,
        now: Instant,
        parse: impl FnOnce(&[u8]) -> Option<T>,
    ) -> Lookup<'_, T> {
        self.current_with_reader(path, now, |b: Vec<u8>| parse(&b), read_snapshot_bytes)
    }

    fn current_with_reader<R>(
        &mut self,
        path: &Path,
        now: Instant,
        parse: impl FnOnce(R) -> Option<T>,
        read: impl FnOnce(&Path, Fingerprint) -> Result<R, Failure>,
    ) -> Lookup<'_, T> {
        let fingerprint = match fingerprint(path) {
            Ok(fingerprint) => fingerprint,
            Err(failure) => {
                self.fingerprint = None;
                self.entry = None;
                self.retry_at = None;
                return self.result(now, false, Some(failure));
            }
        };
        if fingerprint.size == 0 {
            self.fingerprint = Some(fingerprint);
            self.entry = None;
            self.retry_at = None;
            return self.result(now, false, None);
        }
        if self.fingerprint == Some(fingerprint)
            && (self.entry.is_some() || self.retry_at.is_some_and(|deadline| now < deadline))
        {
            return self.result(now, false, None);
        }

        self.entry = None;
        self.fingerprint = Some(fingerprint);
        self.retry_at = Some(now + RETRY_INTERVAL);
        let result = read(path, fingerprint).and_then(|content| {
            let entry = parse(content).ok_or(Failure::InvalidKeybox)?;
            if self::fingerprint(path)? != fingerprint {
                return Err(Failure::ChangedWhileReading);
            }
            Ok(entry)
        });
        match result {
            Ok(entry) => {
                self.entry = Some(entry);
                self.retry_at = None;
                self.result(now, true, None)
            }
            Err(failure) => self.result(now, false, Some(failure)),
        }
    }

    fn result(&mut self, now: Instant, loaded: bool, failure: Option<Failure>) -> Lookup<'_, T> {
        let diagnostic = failure.filter(|_| {
            self.last_diagnostic
                .is_none_or(|last| now.saturating_duration_since(last) >= DIAGNOSTIC_INTERVAL)
        });
        if diagnostic.is_some() {
            self.last_diagnostic = Some(now);
        }
        Lookup { entry: self.entry.as_ref(), loaded, diagnostic }
    }
}

fn fingerprint(path: &Path) -> Result<Fingerprint, Failure> {
    let metadata = fs::symlink_metadata(path).map_err(|error| Failure::io("lstat", error))?;
    if !metadata.is_file() {
        return Err(Failure::NotRegularFile);
    }
    if metadata.len() > MAX_KEYBOX_BYTES as u64 {
        return Err(Failure::InvalidKeybox);
    }
    Ok(Fingerprint::of(&metadata))
}

fn read_snapshot(path: &Path, expected: Fingerprint) -> Result<String, Failure> {
    let bytes = read_snapshot_bytes(path, expected)?;
    String::from_utf8(bytes).map_err(|_| Failure::InvalidKeybox)
}

fn read_snapshot_bytes(path: &Path, expected: Fingerprint) -> Result<Vec<u8>, Failure> {
    let mut file = File::open(path).map_err(|error| Failure::io("open", error))?;
    let before = file.metadata().map_err(|error| Failure::io("fstat", error))?;
    if Fingerprint::of(&before) != expected {
        return Err(Failure::ChangedWhileReading);
    }
    let mut content = Vec::with_capacity(expected.size as usize);
    file.read_to_end(&mut content).map_err(|error| Failure::io("read", error))?;
    let after = file.metadata().map_err(|error| Failure::io("fstat", error))?;
    if Fingerprint::of(&after) != expected {
        return Err(Failure::ChangedWhileReading);
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{FileTimes, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture {
        dir: PathBuf,
        path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "yasvara-cache-test-{}-{}-{}",
                std::process::id(),
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            fs::create_dir(dir.join("installed")).unwrap();
            let path = dir.join("installed/keybox.xml");
            Self { dir, path }
        }

        fn write(&self, content: &[u8]) {
            fs::write(&self.path, content).unwrap();
        }

        fn set_mtime(&self, mtime: SystemTime) {
            File::open(&self.path).unwrap().set_times(FileTimes::new().set_modified(mtime)).unwrap();
        }

        fn replace(&self, content: &[u8], mtime: SystemTime) {
            let staged = self.path.with_extension("next");
            fs::write(&staged, content).unwrap();
            File::open(&staged).unwrap().set_times(FileTimes::new().set_modified(mtime)).unwrap();
            fs::rename(staged, &self.path).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn parse(content: &str) -> Option<String> {
        content.strip_prefix("valid:").map(str::to_owned)
    }

    #[test]
    fn unchanged_success_tombstone_atomic_replace_and_races() {
        let fixture = Fixture::new();
        fixture.write(b"valid:first");
        let mtime = UNIX_EPOCH + Duration::from_secs(123);
        fixture.set_mtime(mtime);
        let mut cache = FileCache::new();
        let now = Instant::now();
        assert!(cache.current(&fixture.path, now, parse).loaded);

        let cached = cache.current_with_reader(
            &fixture.path,
            now + DIAGNOSTIC_INTERVAL,
            |_: String| panic!("unchanged success must not parse"),
            |_, _| panic!("unchanged success must not read"),
        );
        assert!(!cached.loaded);
        assert_eq!(cached.entry.map(String::as_str), Some("first"));

        fixture.replace(b"valid:other", mtime);
        assert_eq!(cache.current(&fixture.path, now, parse).entry.map(String::as_str), Some("other"));

        fixture.replace(b"", SystemTime::now() + Duration::from_secs(1));
        let cleared = cache.current(&fixture.path, now + Duration::from_secs(2), parse);
        assert!(cleared.entry.is_none() && cleared.diagnostic.is_none());

        fixture.write(b"valid:first");
        let raced = cache.current_with_reader(
            &fixture.path,
            now,
            |s: String| parse(&s),
            |path, expected| {
                fixture.replace(b"valid:raced", UNIX_EPOCH);
                read_snapshot(path, expected)
            },
        );
        assert!(matches!(raced.diagnostic, Some(Failure::ChangedWhileReading)));
        assert_eq!(cache.current(&fixture.path, now, parse).entry.map(String::as_str), Some("raced"));

        fs::set_permissions(&fixture.path, Permissions::from_mode(0o600)).unwrap();
        let marker = "nonsensitive-marker-must-not-leak";
        let fail = Failure::io("read", io::Error::new(io::ErrorKind::InvalidData, marker));
        assert!(!fail.to_string().contains(marker));
    }
}
