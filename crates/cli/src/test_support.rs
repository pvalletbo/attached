/// Creates a temporary directory whose path has no symlinked ancestors.
///
/// Hardened state tests intentionally reject symlink traversal. On macOS, the
/// default temporary directory can be spelled through the `/var` symlink, so
/// create test directories below its canonical path instead.
pub(crate) fn canonical_tempdir() -> tempfile::TempDir {
    let temporary_root = std::fs::canonicalize(std::env::temp_dir())
        .expect("could not canonicalize the test temporary directory");
    tempfile::tempdir_in(temporary_root).expect("could not create the test temporary directory")
}
