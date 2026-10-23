use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

use crate::error::{Result, RootError};

/// A synthetic, sandboxed filesystem tree representing diverse real-world and adversarial artifacts.
pub struct SyntheticFixture {
    _temp_dir: TempDir,
    root: PathBuf,
}

impl SyntheticFixture {
    /// Constructs a fully populated synthetic fixture tree.
    pub fn create() -> Result<Self> {
        let temp_dir = tempfile::Builder::new()
            .prefix("root-test-fixture-")
            .tempdir()
            .map_err(|e| RootError::Io {
                path: PathBuf::from("tempdir_creation"),
                source: e,
            })?;

        let root = temp_dir.path().to_path_buf();
        let fixture = Self {
            _temp_dir: temp_dir,
            root,
        };
        fixture.populate()?;
        Ok(fixture)
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Verifies that a path strictly resides within the fixture boundary.
    pub fn assert_within_bounds(&self, candidate: &Path) -> Result<()> {
        let canonical_candidate = candidate.canonicalize().map_err(|e| RootError::Io {
            path: candidate.to_path_buf(),
            source: e,
        })?;
        let canonical_root = self.root.canonicalize().map_err(|e| RootError::Io {
            path: self.root.clone(),
            source: e,
        })?;

        if !canonical_candidate.starts_with(&canonical_root) {
            return Err(RootError::PolicyViolation {
                reason: format!(
                    "Path {:?} escaped synthetic fixture boundary {:?}",
                    candidate, self.root
                ),
            });
        }
        Ok(())
    }

    fn populate(&self) -> Result<()> {
        self.create_normal_temp()?;
        self.create_protected_user_files()?;
        self.create_symlinks()?;
        self.create_hardlinks()?;
        self.create_deep_nesting()?;
        self.create_agent_simulations()?;
        self.create_unusual_names()?;
        self.create_empty_directories()?;
        self.create_permission_scenarios()?;
        Ok(())
    }

    fn write_file(&self, rel_path: &str, content: &[u8]) -> Result<PathBuf> {
        let full_path = self.root.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).map_err(|e| RootError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let mut f = File::create(&full_path).map_err(|e| RootError::Io {
            path: full_path.clone(),
            source: e,
        })?;
        f.write_all(content).map_err(|e| RootError::Io {
            path: full_path.clone(),
            source: e,
        })?;
        Ok(full_path)
    }

    fn create_normal_temp(&self) -> Result<()> {
        self.write_file("tmp_normal/app_cache.tmp", b"synthetic cache buffer data")?;
        self.write_file("tmp_normal/worker.sock.lock", b"12345")?;
        Ok(())
    }

    fn create_protected_user_files(&self) -> Result<()> {
        self.write_file(
            "protected_user/.bashrc",
            b"export PATH=/usr/local/bin:$PATH",
        )?;
        self.write_file(
            "protected_user/.ssh/id_ed25519",
            b"-----BEGIN OPENSSH PRIVATE KEY----- [SYNTHETIC TEST KEY]",
        )?;
        self.write_file(
            "protected_user/Documents/project_plan.txt",
            b"Confidential business plan",
        )?;
        Ok(())
    }

    #[cfg(unix)]
    fn create_symlink(original: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(original, link)
    }

    #[cfg(windows)]
    fn create_symlink(original: &Path, link: &Path) -> std::io::Result<()> {
        if original.is_dir() {
            std::os::windows::fs::symlink_dir(original, link)
        } else {
            std::os::windows::fs::symlink_file(original, link)
        }
    }

    fn create_symlinks(&self) -> Result<()> {
        let symlink_dir = self.root.join("symlinks");
        fs::create_dir_all(&symlink_dir).map_err(|e| RootError::Io {
            path: symlink_dir.clone(),
            source: e,
        })?;

        // 1. Valid relative symlink
        let valid_target = PathBuf::from("../tmp_normal/app_cache.tmp");
        let valid_link = symlink_dir.join("valid_rel.txt");
        let _ = Self::create_symlink(&valid_target, &valid_link);

        // 2. Dangling symlink
        let dangling_target = PathBuf::from("nonexistent_file_98765.log");
        let dangling_link = symlink_dir.join("dangling.txt");
        let _ = Self::create_symlink(&dangling_target, &dangling_link);

        // 3. Jail escape symlink (attempts to escape fixture root)
        let escape_target = PathBuf::from("../../../../../etc/passwd");
        let escape_link = symlink_dir.join("jail_escape.txt");
        let _ = Self::create_symlink(&escape_target, &escape_link);

        // 4. Circular symlink loop (a -> b, b -> a)
        let loop_dir_a = symlink_dir.join("loop_a");
        let loop_dir_b = symlink_dir.join("loop_b");
        let _ = fs::create_dir_all(&loop_dir_a);
        let _ = fs::create_dir_all(&loop_dir_b);
        let _ = Self::create_symlink(&loop_dir_b, &loop_dir_a.join("link_to_b"));
        let _ = Self::create_symlink(&loop_dir_a, &loop_dir_b.join("link_to_a"));

        Ok(())
    }

    fn create_hardlinks(&self) -> Result<()> {
        let origin = self.write_file(
            "hardlinks/shared_inode.dat",
            b"Content shared across multiple hard links",
        )?;
        let link_dest = self.root.join("hardlinks/link_copy_1.dat");
        let link_dest2 = self.root.join("hardlinks/link_copy_2.dat");

        let _ = fs::hard_link(&origin, &link_dest);
        let _ = fs::hard_link(&origin, &link_dest2);
        Ok(())
    }

    fn create_deep_nesting(&self) -> Result<()> {
        let mut deep = self.root.join("nested_deep");
        for i in 1..=12 {
            deep = deep.join(format!("level_{:02}", i));
        }
        fs::create_dir_all(&deep).map_err(|e| RootError::Io {
            path: deep.clone(),
            source: e,
        })?;
        let leaf = deep.join("leaf_artifact.txt");
        let mut f = File::create(&leaf).map_err(|e| RootError::Io {
            path: leaf.clone(),
            source: e,
        })?;
        f.write_all(b"Deeply nested synthetic leaf")
            .map_err(|e| RootError::Io {
                path: leaf,
                source: e,
            })?;
        Ok(())
    }

    fn create_agent_simulations(&self) -> Result<()> {
        // Antigravity simulation
        self.write_file(
            "agent_simulated/gemini/antigravity-cli/brain/active-session-12345/transcript.jsonl",
            b"{\"step\": 1, \"role\": \"user\", \"content\": \"Synthetic prompt\"}\n",
        )?;
        self.write_file(
            "agent_simulated/gemini/antigravity-cli/brain/abandoned-session-67890/scratch/dummy_repo/src/main.rs",
            b"fn main() { println!(\"Synthetic scratchpad\"); }",
        )?;
        self.write_file(
            "agent_simulated/gemini/antigravity-cli/brain/abandoned-session-67890/.system_generated/steps/1/output.txt",
            b"Large command output dump in step 1...",
        )?;
        self.write_file(
            "agent_simulated/gemini/antigravity-cli/log/cli-20261010_080000.log",
            b"Diagnostic CLI execution logs",
        )?;
        self.write_file(
            "agent_simulated/gemini/oauth_creds.json",
            b"{\"access_token\": \"SYNTHETIC_DUMMY_TOKEN\"}",
        )?;

        // Claude Code simulation
        self.write_file(
            "agent_simulated/claude/sessions/session-alpha.json",
            b"{\"session_id\": \"alpha\", \"messages\": 10}",
        )?;
        self.write_file(
            "agent_simulated/claude/sessions/session-alpha.key",
            b"SYNTHETIC_ENCRYPTION_KEY_BYTES",
        )?;
        self.write_file(
            "agent_simulated/claude/shell-snapshots/snapshot-zsh-999.sh",
            b"export SYNTHETIC_ENV_VAR=1\n",
        )?;

        // Leaked empty session-env directories
        let empty_env_1 = self
            .root
            .join("agent_simulated/claude/session-env/01a5fac8-96c8-4cc3-bfd2-d394456abf54");
        let empty_env_2 = self
            .root
            .join("agent_simulated/claude/session-env/072c702d-7598-4f3e-9f89-2e26086d8559");
        let _ = fs::create_dir_all(empty_env_1);
        let _ = fs::create_dir_all(empty_env_2);

        // Tooling simulation (Cargo & npm)
        self.write_file(
            "agent_simulated/workspaces/app1/target/debug/app1",
            b"binary_elf_header_dummy",
        )?;
        self.write_file(
            "agent_simulated/workspaces/app1/node_modules/lodash/index.js",
            b"module.exports = {};",
        )?;
        self.write_file(
            "agent_simulated/workspaces/app1/.git/HEAD",
            b"ref: refs/heads/main\n",
        )?;

        // Active session presence marker for Antigravity
        self.write_file(
            "agent_simulated/gemini/antigravity-cli/presence/session_active.lock",
            b"pid: 1234\n",
        )?;

        // OpenAI Codex simulation
        self.write_file(
            "agent_simulated/cache/openai/prompt_cache_hash_9876.dat",
            b"cached_completion_tokens_binary",
        )?;
        self.write_file(
            "agent_simulated/openai/api_key",
            b"sk-synthetic-dummy-key-never-leak",
        )?;

        // Gemini CLI simulation
        self.write_file(
            "agent_simulated/gemini/tmp/orphan_upload.chunk",
            b"incomplete_multipart_upload_chunk_data",
        )?;
        self.write_file(
            "agent_simulated/gemini/history/input_history.txt",
            b"prompt 1\nprompt 2\n",
        )?;

        // Aider simulation
        self.write_file(
            "agent_simulated/workspaces/app1/.aider.tags.cache.v3",
            b"precomputed_ast_symbol_index_tags_data",
        )?;
        self.write_file(
            "agent_simulated/workspaces/app1/.aider.chat.history.md",
            b"# Aider chat history\nUSER: Add feature\n",
        )?;
        self.write_file(
            "agent_simulated/workspaces/app1/.aider.input.history",
            b"/add src/main.rs\n",
        )?;

        // Python bytecode and pytest cache simulation
        self.write_file(
            "agent_simulated/workspaces/app1/__pycache__/module.cpython-312.pyc",
            b"compiled_bytecode_magic_bytes",
        )?;
        self.write_file(
            "agent_simulated/workspaces/app1/.pytest_cache/v/cache/lastfailed",
            b"{\"test_failure\": true}",
        )?;

        // Shared package store simulation (pnpm content-addressable store)
        self.write_file(
            "agent_simulated/local/share/pnpm/store/v3/files/ab/cdef123456",
            b"shared_content_addressed_file",
        )?;

        // Language server cache simulation
        self.write_file(
            "agent_simulated/cache/rust-analyzer/project_index_123.bin",
            b"precomputed_ast_index_bytes",
        )?;
        self.write_file(
            "agent_simulated/cache/clangd/index/symbol.idx",
            b"clangd_symbol_index_bytes",
        )?;

        // Dev server cache simulation
        self.write_file(
            "agent_simulated/workspaces/app1/.next/cache/webpack/client-development/0.pack",
            b"packed_asset_chunk_cache",
        )?;
        self.write_file(
            "agent_simulated/workspaces/app1/node_modules/.vite/deps/package.json",
            b"{\"name\": \"vite-cache\"}",
        )?;

        // Unknown tool directory simulation
        self.write_file(
            "agent_simulated/unknown_vendor/temp_cache.bin",
            b"unknown_binary_cache_data",
        )?;

        Ok(())
    }

    fn create_unusual_names(&self) -> Result<()> {
        self.write_file("unusual_names/file with spaces.log", b"spaces")?;
        self.write_file(
            "unusual_names/файл-тест-отчет.dat",
            b"unicode cyrillic content",
        )?;
        self.write_file("unusual_names/--leading-dashes.tmp", b"dashes")?;
        #[cfg(unix)]
        {
            self.write_file("unusual_names/\"quoted_name\".txt", b"quotes")?;
            self.write_file("unusual_names/newlines\nin\nname.tmp", b"newlines")?;
        }
        Ok(())
    }

    fn create_empty_directories(&self) -> Result<()> {
        let empty_1 = self.root.join("empty_dirs/orphan_empty_dir_1");
        let empty_nested = self.root.join("empty_dirs/nested_empty/child_empty");
        fs::create_dir_all(&empty_1).map_err(|e| RootError::Io {
            path: empty_1,
            source: e,
        })?;
        fs::create_dir_all(&empty_nested).map_err(|e| RootError::Io {
            path: empty_nested,
            source: e,
        })?;
        Ok(())
    }

    fn create_permission_scenarios(&self) -> Result<()> {
        let ro_dir = self.root.join("permission_scenarios/read_only_folder");
        fs::create_dir_all(&ro_dir).map_err(|e| RootError::Io {
            path: ro_dir.clone(),
            source: e,
        })?;
        let ro_file = ro_dir.join("content.txt");
        fs::write(&ro_file, b"read only text").map_err(|e| RootError::Io {
            path: ro_file,
            source: e,
        })?;

        // On Unix, set read-only permissions (0o555 on directory)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o555));
        }

        Ok(())
    }
}

impl Drop for SyntheticFixture {
    fn drop(&mut self) {
        // Restore permissions on read-only directory so tempdir cleanup succeeds
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let ro_dir = self.root.join("permission_scenarios/read_only_folder");
            let _ = fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o755));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthetic_fixture_generation() {
        let fixture = SyntheticFixture::create().expect("Failed to create synthetic fixture");
        assert!(fixture.path().exists());

        // Verify protected files exist
        assert!(fixture.path().join("protected_user/.bashrc").exists());
        assert!(fixture
            .path()
            .join("protected_user/.ssh/id_ed25519")
            .exists());

        // Verify hard links
        let hardlink1 = fixture.path().join("hardlinks/shared_inode.dat");
        let hardlink2 = fixture.path().join("hardlinks/link_copy_1.dat");
        assert!(hardlink1.exists());
        assert!(hardlink2.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m1 = fs::metadata(&hardlink1).unwrap();
            let m2 = fs::metadata(&hardlink2).unwrap();
            assert_eq!(m1.ino(), m2.ino());
            assert_eq!(m1.nlink(), 3);
        }

        // Verify deep nesting
        let leaf = fixture.path().join("nested_deep/level_01/level_02/level_03/level_04/level_05/level_06/level_07/level_08/level_09/level_10/level_11/level_12/leaf_artifact.txt");
        assert!(leaf.exists());

        // Verify symlinks
        #[cfg(unix)]
        {
            let symlink_valid = fixture.path().join("symlinks/valid_rel.txt");
            assert!(symlink_valid.exists());
        }

        // Verify boundary assertion
        assert!(fixture.assert_within_bounds(&hardlink1).is_ok());
    }
}
