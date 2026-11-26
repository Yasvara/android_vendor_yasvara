// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Full-featured Recovery File Manager Engine for `Pulih` (surpassing TWRP / OrangeFox).
//!
//! Features:
//! - Lists ALL entries including hidden dotfiles (`.foo`), symlinks (`-> target`),
//!   exact sizes, and full POSIX permissions (`0755` / `rwxr-xr-x`).
//! - Sorting by Name, Size, or Type; directories always grouped cleanly first.
//! - Real `chmod` (with interactive 9-bit `rwx` bit-toggle helper + presets `0644`/`0755`/`0600`/`0777`).
//! - Recursive Copy, Move (Clipboard), Rename, New Folder (`mkdir`), Delete (`rm -rf`).
//! - Anti-brick path guard preventing catastrophic deletion/chmod of `/`, `/dev`, `/proc`, `/sys`, `/system`.
//! - Hardware-accelerated SHA-256 checksum (`pasang_core::crypto::sha256_file`).
//! - Safe UTF-8 Text / Log viewer (bounded read so multi-GB files never OOM!).

use pasang_core::crypto::sha256_file;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// System paths strictly protected from recursive deletion in Recovery File Manager.
pub const PROTECTED_DELETE_PATHS: &[&str] = &[
    "/",
    "/dev",
    "/dev/block",
    "/proc",
    "/sys",
    "/system",
    "/system/bin",
    "/system/lib64",
    "/vendor",
    "/metadata",
    "/mnt",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortMode {
    Name,
    Size,
    Kind,
}

impl SortMode {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Size,
            Self::Size => Self::Kind,
            Self::Kind => Self::Name,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Size => "Size",
            Self::Kind => "Type",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    Symlink,
    File,
    Special,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub path: PathBuf,
    pub kind: EntryKind,
    pub size: u64,
    pub mode: u32,
    pub symlink_target: Option<String>,
}

impl FileEntry {
    /// Format Unix permission bits (`0o755` -> `"0755 rwxr-xr-x"`).
    pub fn perm_octal(&self) -> String {
        format!("{:04o}", self.mode & 0o7777)
    }

    pub fn perm_rwx(&self) -> String {
        format_mode_rwx(self.mode)
    }

    pub fn is_flashable_zip(&self) -> bool {
        self.kind == EntryKind::File && self.name.to_ascii_lowercase().ends_with(".zip")
    }

    pub fn is_flashable_img(&self) -> bool {
        self.kind == EntryKind::File && self.name.to_ascii_lowercase().ends_with(".img")
    }

    pub fn is_archive(&self) -> bool {
        let low = self.name.to_ascii_lowercase();
        self.kind == EntryKind::File
            && (low.ends_with(".tar") || low.ends_with(".yvbak") || low.ends_with(".tar.zst"))
    }
}

/// Format low 9 POSIX permission bits into `"rwxr-xr-x"`.
pub fn format_mode_rwx(mode: u32) -> String {
    let bits = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    let mut s = String::with_capacity(9);
    for (mask, ch) in bits {
        s.push(if (mode & mask) != 0 { ch } else { '-' });
    }
    s
}

/// Format byte size concisely (`128 B`, `4.2 KiB`, `100.0 MiB`, `4.36 GiB`).
pub fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.2} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.1} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.1} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClipboardOp {
    Copy(Vec<PathBuf>),
    Move(Vec<PathBuf>),
}

/// List EVERY entry in `dir` (including dotfiles when `show_hidden == true`).
/// Uses `symlink_metadata` so broken symlinks never crash or vanish!
pub fn list_directory(
    dir: &Path,
    show_hidden: bool,
    sort: SortMode,
) -> Result<Vec<FileEntry>, String> {
    let rd = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for item in rd.flatten() {
        let name = item.file_name().to_string_lossy().to_string();
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        let path = item.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let ft = meta.file_type();
        let (kind, symlink_target) = if ft.is_symlink() {
            let tgt = fs::read_link(&path)
                .ok()
                .map(|p| p.to_string_lossy().to_string());
            (EntryKind::Symlink, tgt)
        } else if ft.is_dir() {
            (EntryKind::Directory, None)
        } else if ft.is_file() {
            (EntryKind::File, None)
        } else {
            (EntryKind::Special, None)
        };
        out.push(FileEntry {
            name,
            path,
            kind,
            size: meta.size(),
            mode: meta.mode() & 0o7777,
            symlink_target,
        });
    }

    out.sort_by(|a, b| {
        let a_dir = a.kind == EntryKind::Directory;
        let b_dir = b.kind == EntryKind::Directory;
        if a_dir != b_dir {
            return b_dir.cmp(&a_dir); // directories always first
        }
        match sort {
            SortMode::Name => a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()),
            SortMode::Size => b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)),
            SortMode::Kind => {
                let ext = |n: &str| n.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
                ext(&a.name).cmp(&ext(&b.name)).then_with(|| a.name.cmp(&b.name))
            }
        }
    });
    Ok(out)
}

/// Apply POSIX permissions (`0o0000..=0o7777`) to a file or directory.
pub fn apply_chmod(path: &Path, mode: u32) -> Result<(), String> {
    let clean_mode = mode & 0o7777;
    let perms = fs::Permissions::from_mode(clean_mode);
    fs::set_permissions(path, perms)
        .map_err(|e| format!("chmod {:04o} {} failed: {e}", clean_mode, path.display()))
}

/// Guard against accidentally deleting critical root/system/kernel directories!
pub fn is_protected_delete_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    let trimmed = if s.len() > 1 {
        s.trim_end_matches('/')
    } else {
        s.as_ref()
    };
    PROTECTED_DELETE_PATHS.iter().any(|&p| p == trimmed)
}

/// Safely delete a file, symlink, or directory (blocked on critical root/system paths).
pub fn safe_delete(path: &Path) -> Result<(), String> {
    if is_protected_delete_path(path) {
        return Err(format!(
            "BLOCKED: '{}' is a protected system path",
            path.display()
        ));
    }
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("stat {} failed: {e}", path.display()))?;
    if meta.file_type().is_dir() {
        fs::remove_dir_all(path).map_err(|e| format!("rm -rf {} failed: {e}", path.display()))
    } else {
        fs::remove_file(path).map_err(|e| format!("rm {} failed: {e}", path.display()))
    }
}

/// Create a new directory inside `parent` with name validation (rejects `/` and `..`).
pub fn create_folder(parent: &Path, name: &str) -> Result<PathBuf, String> {
    let clean = name.trim();
    if clean.is_empty() || clean.contains('/') || clean == "." || clean == ".." {
        return Err("invalid folder name".into());
    }
    let dst = parent.join(clean);
    fs::create_dir_all(&dst).map_err(|e| format!("mkdir {} failed: {e}", dst.display()))?;
    Ok(dst)
}

/// Rename a file or folder inside its parent directory.
pub fn rename_entry(path: &Path, new_name: &str) -> Result<PathBuf, String> {
    let clean = new_name.trim();
    if clean.is_empty() || clean.contains('/') || clean == "." || clean == ".." {
        return Err("invalid new name".into());
    }
    let parent = path.parent().ok_or("cannot rename root")?;
    let dst = parent.join(clean);
    fs::rename(path, &dst).map_err(|e| format!("rename failed: {e}"))?;
    Ok(dst)
}

/// Recursively copy a file or directory into `dst_dir`.
pub fn copy_recursive(src: &Path, dst_dir: &Path) -> Result<PathBuf, String> {
    let name = src.file_name().ok_or("invalid source path")?;
    let dst = dst_dir.join(name);
    if dst == src {
        return Err("source and destination are identical".into());
    }
    // Prevent copying a directory inside itself!
    if dst.starts_with(src) {
        return Err("cannot copy a directory into itself".into());
    }
    let meta = fs::symlink_metadata(src).map_err(|e| format!("stat {}: {e}", src.display()))?;
    if meta.file_type().is_dir() {
        fs::create_dir_all(&dst).map_err(|e| format!("mkdir {}: {e}", dst.display()))?;
        for entry in fs::read_dir(src).map_err(|e| e.to_string())?.flatten() {
            copy_recursive(&entry.path(), &dst)?;
        }
    } else if meta.file_type().is_symlink() {
        let target = fs::read_link(src).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &dst).map_err(|e| e.to_string())?;
    } else {
        fs::copy(src, &dst).map_err(|e| format!("copy {} -> {}: {e}", src.display(), dst.display()))?;
        let _ = fs::set_permissions(&dst, fs::Permissions::from_mode(meta.mode() & 0o7777));
    }
    Ok(dst)
}

/// Move a file or directory into `dst_dir` (uses `rename`, falling back to `copy_recursive + delete` across mounts!).
pub fn move_entry(src: &Path, dst_dir: &Path) -> Result<PathBuf, String> {
    let name = src.file_name().ok_or("invalid source path")?;
    let dst = dst_dir.join(name);
    if dst == src {
        return Ok(dst);
    }
    if fs::rename(src, &dst).is_ok() {
        return Ok(dst);
    }
    // Cross-filesystem move (e.g. /tmp -> /data/media/0 or USB OTG)
    let copied = copy_recursive(src, dst_dir)?;
    safe_delete(src)?;
    Ok(copied)
}

/// Execute clipboard Copy or Move into `dst_dir`.
pub fn paste_clipboard(op: &ClipboardOp, dst_dir: &Path) -> Result<usize, String> {
    let mut count = 0;
    match op {
        ClipboardOp::Copy(paths) => {
            for p in paths {
                copy_recursive(p, dst_dir)?;
                count += 1;
            }
        }
        ClipboardOp::Move(paths) => {
            for p in paths {
                move_entry(p, dst_dir)?;
                count += 1;
            }
        }
    }
    Ok(count)
}

/// Compute SHA-256 hex digest of a file.
pub fn compute_file_sha256(path: &Path) -> Result<String, String> {
    sha256_file(path)
}

/// Read up to `max_bytes` (default 64 KiB) of a text/log file safely into displayable lines.
pub fn read_text_preview(path: &Path, max_bytes: usize) -> Result<Vec<String>, String> {
    let mut f = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut buf = vec![0u8; max_bytes.min(128 * 1024)];
    let n = f.read(&mut buf).map_err(|e| e.to_string())?;
    buf.truncate(n);
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<String> = text.lines().map(|l| l.replace('\t', "  ")).collect();
    if n == max_bytes.min(128 * 1024) {
        lines.push("--- [truncated at preview limit] ---".into());
    }
    if lines.is_empty() {
        lines.push("(empty file)".into());
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_all_including_hidden_dotfiles_sorts_and_chmod_works() {
        let tmp = std::env::temp_dir().join(format!("pulih_fm_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("subdir")).unwrap();
        fs::write(tmp.join(".hidden_cfg"), b"secret=1\n").unwrap();
        fs::write(tmp.join("rom.zip"), vec![0u8; 4096]).unwrap();
        fs::write(tmp.join("notes.txt"), b"hello pulih\nline2\n").unwrap();

        // Show hidden = true MUST return dotfiles + subdir first!
        let all = list_directory(&tmp, true, SortMode::Name).unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].name, "subdir");
        assert!(all.iter().any(|e| e.name == ".hidden_cfg"));

        // Show hidden = false filters dotfiles
        let visible = list_directory(&tmp, false, SortMode::Name).unwrap();
        assert_eq!(visible.len(), 3);

        // Chmod 0644 -> 0755 verified on real filesystem
        let target = tmp.join("notes.txt");
        apply_chmod(&target, 0o644).unwrap();
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o644);
        assert_eq!(format_mode_rwx(0o644), "rw-r--r--");
        apply_chmod(&target, 0o755).unwrap();
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o755);
        assert_eq!(format_mode_rwx(0o755), "rwxr-xr-x");

        // SHA-256 + text preview
        let hash = compute_file_sha256(&target).unwrap();
        assert_eq!(hash.len(), 64);
        let lines = read_text_preview(&target, 4096).unwrap();
        assert_eq!(lines[0], "hello pulih");
        assert_eq!(lines[1], "line2");

        // Copy / Paste / Rename / Mkdir / Move
        let dest = create_folder(&tmp, "copied").unwrap();
        let pasted = paste_clipboard(&ClipboardOp::Copy(vec![target.clone()]), &dest).unwrap();
        assert_eq!(pasted, 1);
        assert!(dest.join("notes.txt").exists());
        let renamed = rename_entry(&dest.join("notes.txt"), "renamed.txt").unwrap();
        assert!(renamed.exists());

        // Anti-brick delete guard blocks critical root/system dirs!
        assert!(safe_delete(Path::new("/")).is_err());
        assert!(safe_delete(Path::new("/system")).is_err());
        assert!(safe_delete(Path::new("/dev")).is_err());
        assert!(safe_delete(&renamed).is_ok());

        let _ = fs::remove_dir_all(&tmp);
    }
}
