use std::fs;
use std::io::{Error, ErrorKind};
use std::path::{Component, Path, PathBuf};
use agnes_common::{ActionRequest, ActionType};

const MAX_SYMLINK_DEPTH: u32 = 32;

/// Determines whether an action request targets a resource that represents a filesystem path.
///
/// Filesystem actions (ReadFile, WriteFile) are always path-bearing.
/// ReadSecret is path-bearing if its target resource is a filesystem path (e.g., /run/secrets/...,
/// ./keys/..., or references an existing filesystem entity).
pub fn is_path_resource(action_type: ActionType, resource: &str) -> bool {
    match action_type {
        ActionType::ReadFile | ActionType::WriteFile => true,
        ActionType::ReadSecret => {
            resource.starts_with('/')
                || resource.starts_with('.')
                || resource.contains('/')
                || resource.contains('\\')
                || Path::new(resource).exists()
                || fs::symlink_metadata(resource).is_ok()
        }
        _ => false,
    }
}

/// Resolves an ActionRequest target to its real, final canonical path on the filesystem
/// if the action is path-bearing.
///
/// Returns Ok(Some(PathBuf)) if it is a path-bearing action and was resolved.
/// Returns Ok(None) if the action does not target a filesystem path.
/// Returns Err(Error) if path resolution fails (e.g. symlink loop, null byte, inaccessible).
pub fn resolve_request_target(request: &ActionRequest) -> Result<Option<PathBuf>, Error> {
    if is_path_resource(request.action_type, &request.target_resource) {
        resolve_real_path(&request.target_resource).map(Some)
    } else {
        Ok(None)
    }
}

/// Resolves a path to its real, final canonical path on the filesystem,
/// following all symbolic links, stripping redundant separators, and
/// resolving all '.' and '..' components.
///
/// Fail-closed: If the path contains null bytes, exceeds symlink recursion limit,
/// or cannot be unambiguously resolved, an error is returned.
pub fn resolve_real_path(raw_path: &str) -> Result<PathBuf, Error> {
    if raw_path.contains('\0') {
        return Err(Error::new(ErrorKind::InvalidInput, "Null byte in path"));
    }
    if raw_path.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "Empty path"));
    }
    if raw_path.starts_with(char::is_whitespace) || raw_path.ends_with(char::is_whitespace) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Leading or trailing whitespace in path",
        ));
    }

    resolve_real_path_bounded(Path::new(raw_path), 0)
}


fn resolve_real_path_bounded(path: &Path, depth: u32) -> Result<PathBuf, Error> {
    if depth > MAX_SYMLINK_DEPTH {
        return Err(Error::new(ErrorKind::InvalidInput, "Symlink resolution loop or depth exceeded"));
    }

    // 1. Direct canonicalize: follows all symlinks to an existing target
    if let Ok(canonical) = path.canonicalize() {
        return Ok(canonical);
    }

    // 2. If path itself exists as a symlink (e.g. broken symlink to a non-existent file)
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            let target = fs::read_link(path)?;
            let full_target = if target.is_relative() {
                if let Some(parent) = path.parent() {
                    parent.join(target)
                } else {
                    target
                }
            } else {
                target
            };
            return resolve_real_path_bounded(&full_target, depth + 1);
        }
    }

    // 3. For paths where the leaf file does not exist yet (e.g. newly created file or nonexistent target):
    // Walk up ancestors to find the nearest existing directory, canonicalize that directory (which
    // follows all symlinks leading to that directory), and append the remaining leaf components.
    let mut existing_ancestor = path;
    let mut trailing_components = Vec::new();

    while !existing_ancestor.exists() {
        if let Ok(meta) = fs::symlink_metadata(existing_ancestor) {
            if meta.file_type().is_symlink() {
                let target = fs::read_link(existing_ancestor)?;
                let full_target = if target.is_relative() {
                    if let Some(p) = existing_ancestor.parent() {
                        p.join(target)
                    } else {
                        target
                    }
                } else {
                    target
                };
                let mut reconstructed = full_target;
                for comp in trailing_components.into_iter().rev() {
                    reconstructed.push(comp);
                }
                return resolve_real_path_bounded(&reconstructed, depth + 1);
            }
        }

        if let Some(name) = existing_ancestor.file_name() {
            trailing_components.push(name.to_os_string());
            if let Some(parent) = existing_ancestor.parent() {
                existing_ancestor = parent;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if let Ok(canonical_ancestor) = existing_ancestor.canonicalize() {
        let mut resolved = canonical_ancestor;
        for comp in trailing_components.into_iter().rev() {
            resolved.push(comp);
        }
        Ok(normalize_lexical_pathbuf(&resolved))
    } else {
        Err(Error::new(ErrorKind::NotFound, format!("Cannot resolve real path for '{}'", path.display())))
    }
}

pub fn normalize_lexical_pathbuf(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_trailing_whitespace() {
        let err = resolve_real_path("/tmp/test_file.txt ").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "Leading or trailing whitespace in path");
    }

    #[test]
    fn test_rejects_leading_whitespace() {
        let err = resolve_real_path(" /tmp/test_file.txt").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "Leading or trailing whitespace in path");
    }

    #[test]
    fn test_rejects_tab_and_newline_whitespace() {
        let err_tab = resolve_real_path("\t/tmp/test_file.txt").unwrap_err();
        assert_eq!(err_tab.kind(), ErrorKind::InvalidInput);

        let err_nl = resolve_real_path("/tmp/test_file.txt\n").unwrap_err();
        assert_eq!(err_nl.kind(), ErrorKind::InvalidInput);

        let err_cr = resolve_real_path("/tmp/test_file.txt\r").unwrap_err();
        assert_eq!(err_cr.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_rejects_empty_and_whitespace_only() {
        let err_empty = resolve_real_path("").unwrap_err();
        assert_eq!(err_empty.kind(), ErrorKind::InvalidInput);
        assert_eq!(err_empty.to_string(), "Empty path");

        let err_ws = resolve_real_path("   ").unwrap_err();
        assert_eq!(err_ws.kind(), ErrorKind::InvalidInput);
        assert_eq!(err_ws.to_string(), "Leading or trailing whitespace in path");
    }

    #[test]
    fn test_rejects_null_byte() {
        let err = resolve_real_path("/tmp/test\0file.txt").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "Null byte in path");
    }
}
