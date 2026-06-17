# Skill permission manifests

Every observe/analyze/report skill ships a `manifest.json` beside its `SKILL.md`.
It is the **single declaration** of what the skill may touch. `lib/preflight.sh`
collates every manifest through the resolvers (`lib/distro.sh`, `lib/profile.sh`)
into the Claude allowlist (`.claude/settings.local.json`). Add a skill → edit only
its manifest; the next preflight widens the allowlist.

claude-watchman runs as **root** (no `watchman` user, no `/etc/sudoers.d/watchman`),
so the allowlist is the one privilege artifact — root invokes the read/observe
commands directly. The `needs_sudo` flag below is retained for a possible future
non-root deployment, but it generates no sudoers file today.

```json
{
  "skill": "audit-system",          // must match the SKILL.md frontmatter name
  "stage": "grammar",               // grammar | logic | rhetoric
  "reads": [                        // resolver tokens OR literal paths
    "log_path_lynis",               //   token: resolved by calling the distro.sh fn
    "/etc/ssh"                      //   literal: granted as the containing dir tree
  ],
  "commands": [                     // concrete command families this skill runs
    { "family": "lynis", "args": "*", "needs_sudo": true }
  ],
  "resolver_ops": [                 // LOGICAL ops expanded per family by preflight
    "pkg_query", "service_status", "journal_read",
    "net_connections", "firewall_list", "integrity_verify", "mac_status"
  ],
  "fixes": []                       // mutating families used ONLY by the operator-run
                                    // fixer. preflight DELIBERATELY ignores these, so
                                    // they never enter the loop's observe allowlist.
}
```

**Rules**
- A resolver token is any function name in `lib/distro.sh` (`log_path_auth`,
  `log_path_webserver`, `log_path_lynis`). A token that resolves to the journald
  sentinel produces no `Read` rule — `journal_read` covers it via `journalctl`.
- `needs_sudo: true` emits a `Bash(sudo <cmd>)` allow rule (running as root, the
  `sudo` prefix is a harmless no-op and needs no sudoers grant). `false` emits the
  bare `Bash(<cmd>)` allow rule.
- Declare the **minimum**. Least privilege is the default: a skill that touches
  nothing privileged declares nothing privileged.
- `fixes` is documentation of the fixer's mutating surface; it is never granted to
  the unattended loop (scope = Observe + Report). This is the permission seatbelt
  that reinforces the risk tiers from the other side.
