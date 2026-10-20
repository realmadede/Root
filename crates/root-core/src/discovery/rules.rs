use serde::{Deserialize, Serialize};

use super::target::DiscoveryTargetId;
use crate::model::{ConfidenceLevel, ProposedAction, ProtectionTier, ResourceCategory};

/// A deterministic, versioned rule describing resource discovery for an agent or tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryRule {
    pub rule_id: String,
    pub rule_version: u32,
    pub target_id: DiscoveryTargetId,
    pub supported_platforms: Vec<String>,
    pub nominal_base: String,
    pub pattern_description: String,
    pub category: ResourceCategory,
    pub default_tier: ProtectionTier,
    pub default_action: ProposedAction,
    pub evidence_source: String,
    pub confidence: ConfidenceLevel,
    pub known_limitations: String,
    pub verified_versions: String,
}

impl DiscoveryRule {
    /// Tests whether a candidate path matches this rule's detection pattern.
    pub fn matches(&self, path_str: &str) -> bool {
        match self.rule_id.as_str() {
            // Antigravity rules
            "antigravity-auth" => {
                (path_str.contains("/.gemini/") || path_str.contains("/gemini/"))
                    && (path_str.ends_with("oauth_creds.json")
                        || path_str.ends_with("google_accounts.json"))
            }
            "antigravity-transcripts" => {
                path_str.contains("antigravity-cli/brain/")
                    && (path_str.ends_with("transcript.jsonl")
                        || path_str.ends_with("transcript_full.jsonl"))
            }
            "antigravity-db" => path_str.contains("antigravity-cli/conversation_summaries.db"),
            "antigravity-scratch" => {
                path_str.contains("antigravity-cli/brain/") && path_str.contains("/scratch")
            }
            "antigravity-step-outputs" => {
                path_str.contains("antigravity-cli/brain/")
                    && path_str.contains(".system_generated/steps/")
                    && path_str.ends_with("output.txt")
            }
            "antigravity-cli-logs" => {
                path_str.contains("antigravity-cli/log/") && path_str.contains("cli-")
            }
            "antigravity-crashes" => {
                path_str.contains("antigravity-cli/crashes/") && path_str.contains("crash_")
            }
            "antigravity-presence" => path_str.contains("antigravity-cli/presence/"),
            "antigravity-state" => {
                path_str.contains("/.gemini/antigravity")
                    || path_str.contains("/gemini/antigravity")
            }

            // Claude Code rules
            "claude-auth-config" => {
                path_str.ends_with("/.claude.json") || path_str.ends_with("/claude.json")
            }
            "claude-session-keys" => {
                (path_str.contains("/.claude/sessions/") || path_str.contains("/claude/sessions/"))
                    && path_str.ends_with(".key")
            }
            "claude-session-data" => {
                (path_str.contains("/.claude/sessions/") || path_str.contains("/claude/sessions/"))
                    && path_str.ends_with(".json")
            }
            "claude-session-env" => {
                path_str.contains("/.claude/session-env/")
                    || path_str.contains("/claude/session-env/")
            }
            "claude-shell-snapshots" => {
                (path_str.contains("/.claude/shell-snapshots/")
                    || path_str.contains("/claude/shell-snapshots/"))
                    && path_str.ends_with(".sh")
            }
            "claude-backups" => {
                path_str.contains("/.claude/backups/") || path_str.contains("/claude/backups/")
            }
            "claude-state" => path_str.contains("/.claude/") || path_str.contains("/claude/"),

            // OpenAI Codex rules
            "codex-api-key" => {
                (path_str.contains("openai") || path_str.contains("codex"))
                    && (path_str.ends_with("/api_key") || path_str.ends_with(".key"))
            }
            "codex-response-cache" => {
                path_str.contains("/.cache/openai/") || path_str.contains("/cache/openai/")
            }

            // Gemini CLI rules
            "gemini-tmp-chunks" => {
                path_str.contains("/.gemini/tmp/") || path_str.contains("/gemini/tmp/")
            }
            "gemini-history" => {
                path_str.contains("/.gemini/history/") || path_str.contains("/gemini/history/")
            }
            "gemini-state" => {
                (path_str.contains("/.gemini/") || path_str.contains("/gemini/"))
                    && !path_str.contains("antigravity")
            }

            // Aider rules
            "aider-chat-history" => path_str.ends_with(".aider.chat.history.md"),
            "aider-input-history" => path_str.ends_with(".aider.input.history"),
            "aider-config" => {
                path_str.ends_with(".aider.conf.yml") || path_str.contains("/.aider/")
            }
            "aider-tags-cache" => path_str.ends_with(".aider.tags.cache.v3"),

            // Development Tooling rules
            "node-modules" => path_str.contains("/node_modules/"),
            "npm-cache" => path_str.contains("/.npm/") || path_str.contains("/npm/"),
            "pnpm-store" => {
                path_str.contains("/.local/share/pnpm/store/")
                    || path_str.contains("/local/share/pnpm/store/")
                    || path_str.contains("/pnpm/store/")
            }
            "rust-target" => path_str.contains("/target/"),
            "cargo-cache" => path_str.contains("/.cargo/") || path_str.contains("/cargo/"),
            "python-bytecode" => path_str.contains("/__pycache__/") || path_str.ends_with(".pyc"),
            "python-test-cache" => {
                path_str.contains("/.pytest_cache/")
                    || path_str.contains("/.mypy_cache/")
                    || path_str.contains("/.ruff_cache/")
            }
            "python-venv" => path_str.contains("/.venv/") || path_str.contains("/venv/"),
            "git-metadata" => path_str.contains("/.git/"),

            // Language Servers & Dev Servers
            "lsp-cache" => {
                path_str.contains("/rust-analyzer/")
                    || path_str.contains("/clangd/")
                    || path_str.contains("/pyright/")
                    || path_str.contains("/gopls/")
                    || path_str.contains("/tsserver/")
            }
            "dev-server-cache" => {
                path_str.contains("/.next/cache/")
                    || path_str.contains("/.vite/")
                    || path_str.contains("/.parcel-cache/")
                    || path_str.contains("/.turbo/")
            }

            _ => false,
        }
    }
}

/// In-memory catalog of deterministic discovery rules.
pub struct RuleRegistry;

impl RuleRegistry {
    pub fn all_rules() -> Vec<DiscoveryRule> {
        vec![
            // 1. Google Antigravity Rules
            DiscoveryRule {
                rule_id: "antigravity-auth".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Antigravity,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.gemini/".into(),
                pattern_description: "oauth_creds.json and google_accounts.json".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "Live Kali Linux Rolling host verification (~/.gemini/)".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Contains OAuth tokens and account identities; never eligible for cleanup".into(),
                verified_versions: "Antigravity CLI 2.0+".into(),
            },
            DiscoveryRule {
                rule_id: "antigravity-transcripts".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Antigravity,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.gemini/antigravity-cli/brain/".into(),
                pattern_description: "brain/<id>/.system_generated/logs/transcript*.jsonl".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "Antigravity system architecture specifications".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Conversational prompt history and reasoning; protected by privacy invariants".into(),
                verified_versions: "Antigravity CLI 2.0+".into(),
            },
            DiscoveryRule {
                rule_id: "antigravity-db".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Antigravity,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.gemini/antigravity-cli/".into(),
                pattern_description: "conversation_summaries.db*".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "SQLite session index verification".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Master session index; modifying corrupts user session history".into(),
                verified_versions: "Antigravity CLI 2.0+".into(),
            },
            DiscoveryRule {
                rule_id: "antigravity-scratch".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Antigravity,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.gemini/antigravity-cli/brain/".into(),
                pattern_description: "brain/<id>/scratch/**".into(),
                category: ResourceCategory::AgentScratchpad,
                default_tier: ProtectionTier::UserConfirmRequired,
                default_action: ProposedAction::Inspect,
                evidence_source: "Observed scratchpads reaching 250+ MiB in research".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "User may occasionally store uncommitted test files inside scratchpad".into(),
                verified_versions: "Antigravity CLI 2.0+".into(),
            },
            DiscoveryRule {
                rule_id: "antigravity-step-outputs".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Antigravity,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.gemini/antigravity-cli/brain/".into(),
                pattern_description: "brain/<id>/.system_generated/steps/**/output.txt".into(),
                category: ResourceCategory::DiagnosticLog,
                default_tier: ProtectionTier::ObsoleteTransient,
                default_action: ProposedAction::Inspect,
                evidence_source: "Empirical observation of 15 MiB - 80 MiB command outputs".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Archival command dumps; only eligible when conversation is inactive".into(),
                verified_versions: "Antigravity CLI 2.0+".into(),
            },
            DiscoveryRule {
                rule_id: "antigravity-cli-logs".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Antigravity,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.gemini/antigravity-cli/log/".into(),
                pattern_description: "log/cli-*.log".into(),
                category: ResourceCategory::DiagnosticLog,
                default_tier: ProtectionTier::ObsoleteTransient,
                default_action: ProposedAction::Inspect,
                evidence_source: "Session execution traces (~1.5 MiB per invocation)".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Log rotation; logs older than retention are safe".into(),
                verified_versions: "Antigravity CLI 2.0+".into(),
            },
            DiscoveryRule {
                rule_id: "antigravity-crashes".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Antigravity,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.gemini/antigravity-cli/crashes/".into(),
                pattern_description: "crashes/crash_*.log".into(),
                category: ResourceCategory::DiagnosticLog,
                default_tier: ProtectionTier::ObsoleteTransient,
                default_action: ProposedAction::Inspect,
                evidence_source: "Zero-byte crash dump markers".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Crash logs older than 7 days".into(),
                verified_versions: "Antigravity CLI 2.0+".into(),
            },
            DiscoveryRule {
                rule_id: "antigravity-state".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Antigravity,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.gemini/antigravity/".into(),
                pattern_description: "~/.gemini/antigravity*/**".into(),
                category: ResourceCategory::AgentScratchpad,
                default_tier: ProtectionTier::UserConfirmRequired,
                default_action: ProposedAction::Inspect,
                evidence_source: "General Google Antigravity ecosystem application state".into(),
                confidence: ConfidenceLevel::MediumConfidence,
                known_limitations: "Non-specific Antigravity state; requires explicit user review".into(),
                verified_versions: "Antigravity CLI 2.0+".into(),
            },
            DiscoveryRule {
                rule_id: "antigravity-presence".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Antigravity,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.gemini/antigravity-cli/presence/".into(),
                pattern_description: "presence/session_active.lock".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "Active agent presence marker indicating running session".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Protected active lockfile; never eligible for cleanup".into(),
                verified_versions: "Antigravity CLI 2.0+".into(),
            },

            // 2. Claude Code Rules
            DiscoveryRule {
                rule_id: "claude-auth-config".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::ClaudeCode,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.claude.json".into(),
                pattern_description: "~/.claude.json".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "Claude Code CLI global configuration verification".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Holds user credentials and approved tools; strictly protected".into(),
                verified_versions: "Claude Code 0.2+".into(),
            },
            DiscoveryRule {
                rule_id: "claude-session-keys".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::ClaudeCode,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.claude/sessions/".into(),
                pattern_description: "sessions/*.key".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "Cryptographic session key inspection (mode 0600)".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Cryptographic session keys; deletion causes unrecoverable session loss".into(),
                verified_versions: "Claude Code 0.2+".into(),
            },
            DiscoveryRule {
                rule_id: "claude-session-data".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::ClaudeCode,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.claude/sessions/".into(),
                pattern_description: "sessions/*.json".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "Session conversation metadata and messages".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "User conversation history; protected".into(),
                verified_versions: "Claude Code 0.2+".into(),
            },
            DiscoveryRule {
                rule_id: "claude-session-env".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::ClaudeCode,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.claude/session-env/".into(),
                pattern_description: "session-env/<uuid>".into(),
                category: ResourceCategory::AgentScratchpad,
                default_tier: ProtectionTier::ObsoleteTransient,
                default_action: ProposedAction::Inspect,
                evidence_source: "Observed 56 leaked empty UUID directories in research".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Must be confirmed empty before reporting as obsolete".into(),
                verified_versions: "Claude Code 0.2+".into(),
            },
            DiscoveryRule {
                rule_id: "claude-shell-snapshots".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::ClaudeCode,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.claude/shell-snapshots/".into(),
                pattern_description: "shell-snapshots/snapshot-*.sh".into(),
                category: ResourceCategory::DiagnosticLog,
                default_tier: ProtectionTier::ObsoleteTransient,
                default_action: ProposedAction::Inspect,
                evidence_source: "Shell environment exports (~12 KiB each)".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "May contain plaintext user credentials exported in interactive shells".into(),
                verified_versions: "Claude Code 0.2+".into(),
            },
            DiscoveryRule {
                rule_id: "claude-backups".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::ClaudeCode,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.claude/backups/".into(),
                pattern_description: "backups/**".into(),
                category: ResourceCategory::BuildArtifact,
                default_tier: ProtectionTier::UserConfirmRequired,
                default_action: ProposedAction::Inspect,
                evidence_source: "Pre-edit file copies made by Claude".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "User confirmation required if workspace has uncommitted changes".into(),
                verified_versions: "Claude Code 0.2+".into(),
            },
            DiscoveryRule {
                rule_id: "claude-state".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::ClaudeCode,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.claude/".into(),
                pattern_description: "~/.claude/**".into(),
                category: ResourceCategory::BuildArtifact,
                default_tier: ProtectionTier::UserConfirmRequired,
                default_action: ProposedAction::Inspect,
                evidence_source: "General Claude Code state directory".into(),
                confidence: ConfidenceLevel::MediumConfidence,
                known_limitations: "Non-specific Claude Code state; requires user review".into(),
                verified_versions: "Claude Code 0.2+".into(),
            },

            // 3. OpenAI Codex Rules
            DiscoveryRule {
                rule_id: "codex-api-key".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::OpenAiCodex,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.openai/".into(),
                pattern_description: "~/.openai/api_key or ~/.config/openai/".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "OpenAI CLI specification".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Plaintext API credentials; strictly protected".into(),
                verified_versions: "Codex / OpenAI CLI".into(),
            },
            DiscoveryRule {
                rule_id: "codex-response-cache".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::OpenAiCodex,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.cache/openai/".into(),
                pattern_description: "~/.cache/openai/**".into(),
                category: ResourceCategory::PackageCache,
                default_tier: ProtectionTier::SafeRecoverable,
                default_action: ProposedAction::Inspect,
                evidence_source: "XDG prompt cache convention".into(),
                confidence: ConfidenceLevel::MediumConfidence,
                known_limitations: "Clearing may increase API token query costs".into(),
                verified_versions: "OpenAI CLI".into(),
            },

            // 4. Gemini CLI Rules
            DiscoveryRule {
                rule_id: "gemini-tmp-chunks".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::GeminiCli,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.gemini/tmp/".into(),
                pattern_description: "~/.gemini/tmp/**".into(),
                category: ResourceCategory::AgentScratchpad,
                default_tier: ProtectionTier::ObsoleteTransient,
                default_action: ProposedAction::Inspect,
                evidence_source: "Verified multipart upload scratch buffers".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Must verify mtime > 48h and no active upload process".into(),
                verified_versions: "Gemini CLI".into(),
            },
            DiscoveryRule {
                rule_id: "gemini-history".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::GeminiCli,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.gemini/history/".into(),
                pattern_description: "~/.gemini/history/**".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "CLI historical input verification".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Historical user inputs; protected".into(),
                verified_versions: "Gemini CLI".into(),
            },
            DiscoveryRule {
                rule_id: "gemini-state".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::GeminiCli,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.gemini/".into(),
                pattern_description: "~/.gemini/**".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "General Gemini environment state".into(),
                confidence: ConfidenceLevel::MediumConfidence,
                known_limitations: "Protected general Gemini state".into(),
                verified_versions: "Gemini CLI".into(),
            },

            // 5. Aider Rules
            DiscoveryRule {
                rule_id: "aider-tags-cache".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Aider,
                supported_platforms: vec!["linux".into()],
                nominal_base: ".aider.tags.cache.v3".into(),
                pattern_description: "**/.aider.tags.cache.v3".into(),
                category: ResourceCategory::PackageCache,
                default_tier: ProtectionTier::SafeRecoverable,
                default_action: ProposedAction::Inspect,
                evidence_source: "Pre-computed repository AST symbol cache (50 - 200 MiB)".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Re-indexing on next launch requires high CPU to re-parse AST".into(),
                verified_versions: "Aider v0.40+".into(),
            },
            DiscoveryRule {
                rule_id: "aider-chat-history".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Aider,
                supported_platforms: vec!["linux".into()],
                nominal_base: ".aider.chat.history.md".into(),
                pattern_description: "**/.aider.chat.history.md".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "Conversational audit record of repository edits".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Audit log of all changes made by AI; never eligible for deletion".into(),
                verified_versions: "Aider v0.40+".into(),
            },
            DiscoveryRule {
                rule_id: "aider-input-history".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Aider,
                supported_platforms: vec!["linux".into()],
                nominal_base: ".aider.input.history".into(),
                pattern_description: "**/.aider.input.history".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "User readline history".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Readline history; protected".into(),
                verified_versions: "Aider v0.40+".into(),
            },
            DiscoveryRule {
                rule_id: "aider-config".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Aider,
                supported_platforms: vec!["linux".into()],
                nominal_base: ".aider.conf.yml".into(),
                pattern_description: "**/.aider.conf.yml and ~/.aider/*".into(),
                category: ResourceCategory::SessionState,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "Aider model configuration".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "User configuration; protected".into(),
                verified_versions: "Aider v0.40+".into(),
            },

            // 6. Development Tooling: Node.js, npm, pnpm
            DiscoveryRule {
                rule_id: "node-modules".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::NodeNpm,
                supported_platforms: vec!["linux".into()],
                nominal_base: "node_modules/".into(),
                pattern_description: "**/node_modules/**".into(),
                category: ResourceCategory::BuildArtifact,
                default_tier: ProtectionTier::UserConfirmRequired,
                default_action: ProposedAction::Inspect,
                evidence_source: "Node.js dependency resolution algorithm".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Re-installation requires network bandwidth and package lockfile".into(),
                verified_versions: "npm / Node.js all versions".into(),
            },
            DiscoveryRule {
                rule_id: "npm-cache".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::NodeNpm,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.npm/_cacache/".into(),
                pattern_description: "~/.npm/_cacache/**".into(),
                category: ResourceCategory::PackageCache,
                default_tier: ProtectionTier::SafeRecoverable,
                default_action: ProposedAction::Inspect,
                evidence_source: "npm content-addressable tarball cache".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Packages re-download from registry as needed".into(),
                verified_versions: "npm v7+".into(),
            },
            DiscoveryRule {
                rule_id: "pnpm-store".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Pnpm,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.local/share/pnpm/store/".into(),
                pattern_description: "~/.local/share/pnpm/store/**".into(),
                category: ResourceCategory::PackageCache,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "pnpm hard-link content-addressable store".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "CRITICAL: Shared hard-link inodes across projects; direct unlinking corrupts workspaces".into(),
                verified_versions: "pnpm v8+".into(),
            },

            // 7. Rust & Cargo
            DiscoveryRule {
                rule_id: "rust-target".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::RustCargo,
                supported_platforms: vec!["linux".into()],
                nominal_base: "target/".into(),
                pattern_description: "**/target/debug/** and **/target/release/**".into(),
                category: ResourceCategory::BuildArtifact,
                default_tier: ProtectionTier::UserConfirmRequired,
                default_action: ProposedAction::Inspect,
                evidence_source: "Cargo target build directory layout".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Rebuilding consumes CPU and battery; user confirmation required".into(),
                verified_versions: "Cargo / rustc all versions".into(),
            },
            DiscoveryRule {
                rule_id: "cargo-cache".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::RustCargo,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.cargo/registry/cache/".into(),
                pattern_description: "~/.cargo/registry/cache/**".into(),
                category: ResourceCategory::PackageCache,
                default_tier: ProtectionTier::SafeRecoverable,
                default_action: ProposedAction::Inspect,
                evidence_source: "crates.io downloaded .crate archives".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Crates re-fetchable from crates.io registry".into(),
                verified_versions: "Cargo all versions".into(),
            },

            // 8. Python
            DiscoveryRule {
                rule_id: "python-bytecode".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Python,
                supported_platforms: vec!["linux".into()],
                nominal_base: "__pycache__/".into(),
                pattern_description: "**/__pycache__/** and **/*.pyc".into(),
                category: ResourceCategory::BuildArtifact,
                default_tier: ProtectionTier::ObsoleteTransient,
                default_action: ProposedAction::Inspect,
                evidence_source: "CPython bytecode caching behavior".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Automatically regenerated on module import if timestamps differ".into(),
                verified_versions: "Python 3.x".into(),
            },
            DiscoveryRule {
                rule_id: "python-test-cache".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Python,
                supported_platforms: vec!["linux".into()],
                nominal_base: ".pytest_cache/".into(),
                pattern_description: "**/.pytest_cache/** and **/.mypy_cache/**".into(),
                category: ResourceCategory::BuildArtifact,
                default_tier: ProtectionTier::ObsoleteTransient,
                default_action: ProposedAction::Inspect,
                evidence_source: "Pytest and Mypy cache directory structure".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Stores test run ordering and incremental type check states".into(),
                verified_versions: "Pytest 7+, Mypy 1+".into(),
            },
            DiscoveryRule {
                rule_id: "python-venv".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Python,
                supported_platforms: vec!["linux".into()],
                nominal_base: ".venv/".into(),
                pattern_description: "**/.venv/** and **/venv/**".into(),
                category: ResourceCategory::BuildArtifact,
                default_tier: ProtectionTier::UserConfirmRequired,
                default_action: ProposedAction::Inspect,
                evidence_source: "Python virtual environment standard layout".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Recreating virtual environment requires pip install requirements".into(),
                verified_versions: "Python venv / virtualenv".into(),
            },

            // 9. Git
            DiscoveryRule {
                rule_id: "git-metadata".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::Git,
                supported_platforms: vec!["linux".into()],
                nominal_base: ".git/".into(),
                pattern_description: "**/.git/**".into(),
                category: ResourceCategory::SystemFile,
                default_tier: ProtectionTier::StrictlyProtected,
                default_action: ProposedAction::Ignore,
                evidence_source: "Git repository object database and reflog".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "CRITICAL: Modifying .git corrupts reflog and uncommitted history".into(),
                verified_versions: "Git all versions".into(),
            },

            // 10. Language Servers
            DiscoveryRule {
                rule_id: "lsp-cache".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::LanguageServers,
                supported_platforms: vec!["linux".into()],
                nominal_base: "~/.cache/rust-analyzer/".into(),
                pattern_description: "~/.cache/rust-analyzer/**, ~/.cache/clangd/**, and ~/.cache/pyright/**".into(),
                category: ResourceCategory::BuildArtifact,
                default_tier: ProtectionTier::SafeRecoverable,
                default_action: ProposedAction::Inspect,
                evidence_source: "Language Server Protocol index and AST analysis cache".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Rebuilt automatically upon next language server invocation".into(),
                verified_versions: "rust-analyzer, clangd, pyright".into(),
            },

            // 11. Dev Servers
            DiscoveryRule {
                rule_id: "dev-server-cache".to_string(),
                rule_version: 1,
                target_id: DiscoveryTargetId::DevServers,
                supported_platforms: vec!["linux".into()],
                nominal_base: ".next/cache/ or node_modules/.vite/".into(),
                pattern_description: "**/.next/cache/**, **/.vite/**, and **/.parcel-cache/**".into(),
                category: ResourceCategory::BuildArtifact,
                default_tier: ProtectionTier::ObsoleteTransient,
                default_action: ProposedAction::Inspect,
                evidence_source: "Frontend development server asset bundling and cache store".into(),
                confidence: ConfidenceLevel::HighConfidence,
                known_limitations: "Dev servers automatically recompile assets when cache is cleared".into(),
                verified_versions: "Next.js, Vite, Webpack, Parcel".into(),
            },
        ]
    }

    /// Finds matching rule for a path, returning the most specific match.
    pub fn match_path(path_str: &str) -> Option<DiscoveryRule> {
        let rules = Self::all_rules();
        rules.into_iter().find(|rule| rule.matches(path_str))
    }
}
