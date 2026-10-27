#![cfg(target_os = "linux")]

use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use root_platform::{
    is_openat2_supported, PinnedDirectory, ResolutionError, ResolutionMode, ResolutionOptions,
};

fn default_opts() -> ResolutionOptions {
    ResolutionOptions::default()
}

fn fallback_opts() -> ResolutionOptions {
    ResolutionOptions {
        mode: ResolutionMode::ForceFallback,
        allow_mount_crossing: false,
    }
}

fn openat2_opts() -> ResolutionOptions {
    ResolutionOptions {
        mode: ResolutionMode::ForceOpenat2,
        allow_mount_crossing: false,
    }
}

// 1. Successful opening of a real directory fixture
#[test]
fn test_01_successful_opening_real_directory_fixture() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let pinned = PinnedDirectory::open_root(temp.path()).expect("Open real directory fixture");
    assert!(pinned.raw_fd() >= 0, "Descriptor must be non-negative");

    let id = pinned.identity();
    assert!(id.device_id > 0, "Device ID must be non-zero");
    assert!(id.inode > 0, "Inode number must be non-zero");
    assert!(id.is_same_object(pinned.identity()));
}

// 2. Rejection of a regular file where a directory is required
#[test]
fn test_02_rejection_of_regular_file() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let file_path = temp.path().join("regular_file.txt");
    fs::write(&file_path, b"hello world").expect("Write regular file");

    let res = PinnedDirectory::open_root(&file_path);
    assert!(
        matches!(res, Err(ResolutionError::NotADirectory(_))),
        "Opening a regular file as root directory must fail with NotADirectory"
    );
}

// 3. Rejection of a final-component symlink when the API prohibits it
#[test]
fn test_03_rejection_of_final_component_symlink() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let real_dir = temp.path().join("real_target_dir");
    fs::create_dir(&real_dir).expect("Create real target dir");

    let sym_dir = temp.path().join("symlink_to_dir");
    std::os::unix::fs::symlink(&real_dir, &sym_dir).expect("Create symlink to dir");

    // Root opening must reject symlink at final component
    let root_res = PinnedDirectory::open_root(&sym_dir);
    assert!(
        matches!(root_res, Err(ResolutionError::SymlinkRejected(_))),
        "open_root must reject symlinks via O_NOFOLLOW"
    );

    // Child opening must also reject symlink
    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");
    let child_res = pinned_root.open_child_dir("symlink_to_dir", default_opts());
    assert!(
        matches!(child_res, Err(ResolutionError::SymlinkRejected(_))),
        "open_child_dir must reject symlink components"
    );
}

// 4. Rejection of `.` and `..` where prohibited
#[test]
fn test_04_rejection_of_dot_and_dotdot() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");

    let res_dot = pinned_root.open_child_dir(".", default_opts());
    assert!(
        matches!(res_dot, Err(ResolutionError::InvalidComponent(_))),
        "open_child_dir must reject '.'"
    );

    let res_dotdot = pinned_root.open_child_dir("..", default_opts());
    assert!(
        matches!(res_dotdot, Err(ResolutionError::InvalidComponent(_))),
        "open_child_dir must reject '..'"
    );

    let res_file_dot = pinned_root.open_child_file(".", 0, default_opts());
    assert!(
        matches!(res_file_dot, Err(ResolutionError::InvalidComponent(_))),
        "open_child_file must reject '.'"
    );
}

// 5. Rejection of prohibited multi-component paths in the single-component API
#[test]
fn test_05_rejection_of_prohibited_multicomponent_paths() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let sub_a = temp.path().join("sub_a");
    let sub_b = sub_a.join("sub_b");
    fs::create_dir_all(&sub_b).expect("Create nested directories");

    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");

    let res = pinned_root.open_child_dir("sub_a/sub_b", default_opts());
    assert!(
        matches!(res, Err(ResolutionError::InvalidComponent(_))),
        "Single-component API must reject paths containing slashes"
    );

    let file_res = pinned_root.open_child_file("sub_a/file.txt", 0, default_opts());
    assert!(
        matches!(file_res, Err(ResolutionError::InvalidComponent(_))),
        "Single-component file API must reject paths containing slashes"
    );
}

// 6. Correct handling of nonexistent paths
#[test]
fn test_06_correct_handling_of_nonexistent_paths() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let non_existent = temp.path().join("missing_directory");
    let res_root = PinnedDirectory::open_root(&non_existent);
    assert!(
        matches!(res_root, Err(ResolutionError::NotFound(_))),
        "open_root on missing path must return NotFound"
    );

    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");
    let res_child = pinned_root.open_child_dir("missing_child", default_opts());
    assert!(
        matches!(res_child, Err(ResolutionError::NotFound(_))),
        "open_child_dir on missing child must return NotFound"
    );
}

// 7. Permission-denied behavior where it can be tested reliably without elevated privileges
#[test]
fn test_07_permission_denied_behavior() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let restricted_dir = temp.path().join("restricted_dir");
    fs::create_dir(&restricted_dir).expect("Create restricted dir");

    // Strip execute and read permissions (mode 0000)
    fs::set_permissions(&restricted_dir, fs::Permissions::from_mode(0o000))
        .expect("Set restrictive permissions");

    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");
    let res = pinned_root.open_child_dir("restricted_dir", default_opts());

    // Restore permissions so tempdir can clean up cleanly
    let _ = fs::set_permissions(&restricted_dir, fs::Permissions::from_mode(0o755));

    assert!(
        matches!(res, Err(ResolutionError::PermissionDenied(_))),
        "Opening unreadable directory must fail with PermissionDenied"
    );
}

// 8. Correct descriptor closure on normal drop
#[test]
fn test_08_correct_descriptor_closure_on_normal_drop() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let raw_fd: i32;
    {
        let pinned = PinnedDirectory::open_root(temp.path()).expect("Open root dir");
        raw_fd = pinned.raw_fd();
        assert!(raw_fd >= 0);

        // Verify descriptor is active in kernel
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        assert!(flags >= 0, "Descriptor must be open and valid");
    }
    // `pinned` has been dropped here

    // Verify descriptor has been closed by checking F_GETFD returns EBADF.
    // If the multi-threaded test runner recycled the file descriptor immediately,
    // verify via /proc/self/fd that it no longer points to the temporary directory.
    let flags_after = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
    if flags_after == -1 {
        let err = std::io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
    } else if let Ok(target) = std::fs::read_link(format!("/proc/self/fd/{raw_fd}")) {
        assert_ne!(
            target,
            temp.path(),
            "Descriptor was not closed; still references temp directory"
        );
    }
}

// 9. Error-path descriptor cleanup (no descriptor leak on failure)
#[test]
fn test_09_error_path_descriptor_cleanup() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let file_path = temp.path().join("not_a_dir.dat");
    fs::write(&file_path, b"test payload").expect("Write test file");

    let sub_dir = temp.path().join("sub_dir");
    fs::create_dir(&sub_dir).expect("Create sub dir");

    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");

    // Count open descriptors via /proc/self/fd if available
    fn count_open_fds() -> Option<usize> {
        fs::read_dir("/proc/self/fd").ok().map(|d| d.count())
    }

    let fds_before = count_open_fds();

    // Trigger error paths 100 times across various failure branches:
    // - opening a regular file as a directory (post-open check fails and closes fd)
    // - opening a directory as a file (post-open check fails and closes fd)
    // - opening a nonexistent target
    for _ in 0..100 {
        let err1 = pinned_root.open_child_dir("not_a_dir.dat", default_opts());
        assert!(matches!(err1, Err(ResolutionError::NotADirectory(_))));

        let err2 = pinned_root.open_child_file("sub_dir", 0, default_opts());
        assert!(matches!(err2, Err(ResolutionError::InvalidComponent(_))));

        let err3 = pinned_root.open_child_dir("nonexistent_child", default_opts());
        assert!(matches!(err3, Err(ResolutionError::NotFound(_))));
    }

    let fds_after = count_open_fds();

    if let (Some(b), Some(a)) = (fds_before, fds_after) {
        // In a multi-threaded test runner, other threads opening/closing files can introduce
        // small fluctuations (+/- 10). A leak of 300 operations would increase descriptors by >= 100.
        let diff = (a as isize) - (b as isize);
        assert!(
            diff < 50,
            "Open file descriptor count grew significantly (before: {}, after: {}), indicating an error path leak",
            b, a
        );
    }
}

// 10. Descriptor identity reporting
#[test]
fn test_10_descriptor_identity_reporting() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let child_dir = temp.path().join("reported_child");
    fs::create_dir(&child_dir).expect("Create child dir");

    let stat = fs::metadata(&child_dir).expect("Stat child dir");
    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");

    let pinned_child = pinned_root
        .open_child_dir("reported_child", default_opts())
        .expect("Open child dir");

    let id = pinned_child.identity();
    assert_eq!(id.device_id, stat.dev());
    assert_eq!(id.inode, stat.ino());
    assert_eq!(id.mode & 0o777, stat.mode() & 0o777);
    assert_eq!(id.uid, stat.uid());
}

// 11. `openat2` supported-path behavior where available
#[test]
fn test_11_openat2_supported_path_behavior() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let child_dir = temp.path().join("openat2_test_dir");
    fs::create_dir(&child_dir).expect("Create test dir");

    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");

    if is_openat2_supported() {
        let res = pinned_root.open_child_dir("openat2_test_dir", openat2_opts());
        assert!(
            res.is_ok(),
            "openat2 must succeed when kernel supports capability"
        );
        let child = res.unwrap();
        assert!(child.raw_fd() >= 0);
    } else {
        let res = pinned_root.open_child_dir("openat2_test_dir", openat2_opts());
        assert!(
            matches!(res, Err(ResolutionError::UnsupportedCapability(_))),
            "ForceOpenat2 must return UnsupportedCapability when openat2 is absent"
        );
    }
}

// 12. Explicit behavior when `openat2` is unavailable (forced fallback)
#[test]
fn test_12_explicit_behavior_when_openat2_unavailable() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let child_dir = temp.path().join("fallback_test_dir");
    fs::create_dir(&child_dir).expect("Create test dir");

    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");

    // Force fallback execution using openat(O_NOFOLLOW)
    let res = pinned_root.open_child_dir("fallback_test_dir", fallback_opts());
    assert!(
        res.is_ok(),
        "Defensive fallback via openat(O_NOFOLLOW) must succeed for valid child directory"
    );

    let child = res.unwrap();
    assert!(child.raw_fd() >= 0);
}

// 13. Safe fallback behavior for permitted single-component lookups
#[test]
fn test_13_safe_fallback_single_component_lookups() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let real_dir = temp.path().join("real_sub");
    fs::create_dir(&real_dir).expect("Create real sub");

    let sym_sub = temp.path().join("sym_sub");
    std::os::unix::fs::symlink(&real_dir, &sym_sub).expect("Create symlink");

    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");

    // Valid child succeeds under fallback
    let ok_res = pinned_root.open_child_dir("real_sub", fallback_opts());
    assert!(ok_res.is_ok());

    // Symlink child is rejected under fallback
    let sym_res = pinned_root.open_child_dir("sym_sub", fallback_opts());
    assert!(
        matches!(sym_res, Err(ResolutionError::SymlinkRejected(_))),
        "Fallback must strictly reject symlink components"
    );
}

// 14. Refusal when the fallback cannot satisfy the requested guarantees
#[test]
fn test_14_refusal_when_fallback_cannot_satisfy_guarantees() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");

    // Calling ForceOpenat2 when capability is absent refuses operation
    let opts = openat2_opts();
    if !is_openat2_supported() {
        let res = pinned_root.open_child_dir("any", opts);
        assert!(matches!(
            res,
            Err(ResolutionError::UnsupportedCapability("openat2"))
        ));
    }

    // Invalid component names are refused by fallback
    let res_empty = pinned_root.open_child_dir("", fallback_opts());
    assert!(matches!(
        res_empty,
        Err(ResolutionError::InvalidComponent(_))
    ));
}

// 15. Correct handling of mount-boundary restrictions
#[test]
fn test_15_mount_boundary_restrictions() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let child = temp.path().join("same_device_child");
    fs::create_dir(&child).expect("Create child dir");

    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");

    // Child resides on same device; allow_mount_crossing = false must succeed
    let opts = ResolutionOptions {
        mode: ResolutionMode::Auto,
        allow_mount_crossing: false,
    };
    let res = pinned_root.open_child_dir("same_device_child", opts);
    assert!(res.is_ok(), "Same-device child resolution must succeed");
}

// 16. Multi-component path resolution beneath pinned root
#[test]
fn test_16_resolve_path_beneath_nested_dirs() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let nested = temp.path().join("level1").join("level2").join("level3");
    fs::create_dir_all(&nested).expect("Create nested dirs");

    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");

    let resolved = pinned_root
        .resolve_path_beneath(Path::new("level1/level2/level3"), default_opts())
        .expect("Resolve nested path beneath root");

    let expected_stat = fs::metadata(&nested).expect("Stat nested dir");
    assert_eq!(resolved.identity().inode, expected_stat.ino());

    // Absolute paths must be rejected
    let abs_res = pinned_root.resolve_path_beneath(Path::new("/tmp"), default_opts());
    assert!(matches!(abs_res, Err(ResolutionError::InvalidComponent(_))));

    // Parent directory escapes must be rejected
    let esc_res =
        pinned_root.resolve_path_beneath(Path::new("level1/../../level1"), default_opts());
    assert!(matches!(esc_res, Err(ResolutionError::InvalidComponent(_))));
}

// 17. Pinned file descriptor RAII and file verification
#[test]
fn test_17_open_child_file_raii() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let file_path = temp.path().join("payload.bin");
    let mut f = File::create(&file_path).expect("Create file");
    f.write_all(&[0x42; 256]).expect("Write bytes");

    let pinned_root = PinnedDirectory::open_root(temp.path()).expect("Open root dir");

    let file_fd: i32;
    {
        let pinned_file = pinned_root
            .open_child_file("payload.bin", 0, default_opts())
            .expect("Open child file");

        assert_eq!(pinned_file.size_bytes(), 256);
        file_fd = pinned_file.raw_fd();
        assert!(file_fd >= 0);

        let flags = unsafe { libc::fcntl(file_fd, libc::F_GETFD) };
        assert!(flags >= 0);
    }
    // `pinned_file` dropped here

    let flags_after = unsafe { libc::fcntl(file_fd, libc::F_GETFD) };
    if flags_after == -1 {
        let err = std::io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
    } else if let Ok(target) = std::fs::read_link(format!("/proc/self/fd/{file_fd}")) {
        assert_ne!(
            target, file_path,
            "PinnedFile descriptor was not closed; still references payload.bin"
        );
    }
}

// 18. Descriptor duplication (try_clone) and child existence check
#[test]
fn test_18_try_clone_and_exists_child() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let sub = temp.path().join("child_sub");
    fs::create_dir(&sub).expect("Create dir");

    let pinned = PinnedDirectory::open_root(temp.path()).expect("Open root");
    assert!(pinned.exists_child("child_sub"));
    assert!(!pinned.exists_child("nonexistent"));

    let clone = pinned.try_clone().expect("Clone pinned dir");
    assert_ne!(pinned.raw_fd(), clone.raw_fd());
    assert_eq!(pinned.identity(), clone.identity());
    assert!(clone.exists_child("child_sub"));
}

// 19. Descriptor-relative atomic rename without replacement (rename_child_to)
#[test]
fn test_19_rename_child_to_noreplace() {
    let temp = tempfile::Builder::new()
        .prefix("root-test-descriptor-")
        .tempdir()
        .expect("Create tempdir");

    let src_dir_path = temp.path().join("src_dir");
    let dst_dir_path = temp.path().join("dst_dir");
    fs::create_dir(&src_dir_path).expect("Create src dir");
    fs::create_dir(&dst_dir_path).expect("Create dst dir");

    let file_path = src_dir_path.join("victim.txt");
    fs::write(&file_path, b"test content").expect("Write victim file");

    let src_pinned = PinnedDirectory::open_root(&src_dir_path).expect("Open src pinned");
    let dst_pinned = PinnedDirectory::open_root(&dst_dir_path).expect("Open dst pinned");

    assert!(src_pinned.exists_child("victim.txt"));
    assert!(!dst_pinned.exists_child("renamed.txt"));

    // Rename victim.txt -> renamed.txt
    src_pinned
        .rename_child_to("victim.txt", &dst_pinned, "renamed.txt")
        .expect("Atomic rename");

    assert!(!src_pinned.exists_child("victim.txt"));
    assert!(dst_pinned.exists_child("renamed.txt"));

    // Attempting to rename onto an existing destination must fail with DestinationCollision
    fs::write(src_dir_path.join("victim2.txt"), b"test content 2").expect("Write victim2");
    let err = src_pinned.rename_child_to("victim2.txt", &dst_pinned, "renamed.txt");
    assert!(
        matches!(err, Err(ResolutionError::DestinationCollision(_))),
        "Collision must be rejected with DestinationCollision"
    );
}
