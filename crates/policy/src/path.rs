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

#[cfg(feature = "test-hooks")]
use std::cell::{Cell, RefCell};

#[cfg(feature = "test-hooks")]
type ResolutionHook = Box<dyn Fn(&str) + Send + Sync>;

#[cfg(feature = "test-hooks")]
thread_local! {
    static RESOLUTION_COUNT: Cell<usize> = const { Cell::new(0) };
    static RESOLUTION_HOOK: RefCell<Option<ResolutionHook>> = const { RefCell::new(None) };
}

#[cfg(feature = "test-hooks")]
/// Returns the number of times `resolve_real_path` has been called on the current thread.
pub fn resolution_count() -> usize {
    RESOLUTION_COUNT.with(|c| c.get())
}

#[cfg(feature = "test-hooks")]
/// Resets the resolution counter on the current thread.
pub fn reset_resolution_count() {
    RESOLUTION_COUNT.with(|c| c.set(0));
}

#[cfg(feature = "test-hooks")]
/// Sets an optional hook to run on the current thread after a path is successfully resolved by `resolve_real_path`.
pub fn set_resolution_hook<F>(hook: F)
where
    F: Fn(&str) + Send + Sync + 'static,
{
    RESOLUTION_HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(feature = "test-hooks")]
/// Clears any configured resolution hook on the current thread.
pub fn clear_resolution_hook() {
    RESOLUTION_HOOK.with(|h| {
        *h.borrow_mut() = None;
    });
}

/// Resolves a path to its real, final canonical path on the filesystem,
/// following all symbolic links, stripping redundant separators, and
/// resolving all '.' and '..' components.
///
/// Fail-closed: If the path contains null bytes, exceeds symlink recursion limit,
/// or cannot be unambiguously resolved, an error is returned.
pub fn resolve_real_path(raw_path: &str) -> Result<PathBuf, Error> {
    #[cfg(feature = "test-hooks")]
    RESOLUTION_COUNT.with(|c| c.set(c.get() + 1));

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

    let resolved = resolve_real_path_bounded(Path::new(raw_path), 0)?;

    #[cfg(feature = "test-hooks")]
    RESOLUTION_HOOK.with(|h| {
        if let Some(hook) = h.borrow().as_ref() {
            hook(raw_path);
        }
    });

    Ok(resolved)
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

    #[test]
    fn test_path_normalization_trailing_and_repeated_slashes() {
        let temp = tempfile::tempdir().unwrap();
        let test_dir = temp.path().join("sub_dir");
        std::fs::create_dir_all(&test_dir).unwrap();
        let test_file = test_dir.join("test_file.txt");
        std::fs::write(&test_file, "DATA").unwrap();

        let clean_file = test_file.to_str().unwrap();
        let clean_dir = test_dir.to_str().unwrap();

        let resolved_clean_file = resolve_real_path(clean_file).unwrap();
        let resolved_clean_dir = resolve_real_path(clean_dir).unwrap();

        // 1. Repeated slashes in file path
        let repeated_slash_file = format!("{}///sub_dir//test_file.txt", temp.path().display());
        let resolved_rep_file = resolve_real_path(&repeated_slash_file).unwrap();
        assert_eq!(resolved_rep_file, resolved_clean_file);

        // 2. Dot segments in file path
        let dot_segment_file = format!("{}/./sub_dir/./test_file.txt", temp.path().display());
        let resolved_dot_file = resolve_real_path(&dot_segment_file).unwrap();
        assert_eq!(resolved_dot_file, resolved_clean_file);

        // 3. Repeated slashes in directory path
        let repeated_slash_dir = format!("{}///sub_dir//", temp.path().display());
        let resolved_rep_dir = resolve_real_path(&repeated_slash_dir).unwrap();
        assert_eq!(resolved_rep_dir, resolved_clean_dir);

        // 4. Trailing slash on directory path
        let trailing_slash_dir = format!("{}/", clean_dir);
        let resolved_trailing_dir = resolve_real_path(&trailing_slash_dir).unwrap();
        assert_eq!(resolved_trailing_dir, resolved_clean_dir);

        // 5. Trailing slash on regular file
        let trailing_slash_file = format!("{}/", clean_file);
        let resolved_trailing_file = resolve_real_path(&trailing_slash_file).unwrap();
        assert_eq!(resolved_trailing_file, resolved_clean_file);

        // 6. Non-existent file variants (WriteFile target)
        let non_existent_clean = format!("{}/non_existent.txt", clean_dir);
        let non_existent_rep = format!("{}///sub_dir////non_existent.txt", temp.path().display());
        let non_existent_dot = format!("{}/./sub_dir/./non_existent.txt", temp.path().display());
        let non_existent_slash = format!("{}/non_existent.txt/", clean_dir);

        let res_clean = resolve_real_path(&non_existent_clean).unwrap();
        let res_rep = resolve_real_path(&non_existent_rep).unwrap();
        let res_dot = resolve_real_path(&non_existent_dot).unwrap();
        let res_slash = resolve_real_path(&non_existent_slash).unwrap();

        assert_eq!(res_rep, res_clean);
        assert_eq!(res_dot, res_clean);
        assert_eq!(res_slash, res_clean);
    }
}
