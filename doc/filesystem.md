# Filesystem Snapshot Strategies for bwrap Sandboxing

## Comparison

| Approach | Root? | Host FS requirement | Snapshot speed | Rollback speed | Merge complexity |
|---|---|---|---|---|---|
| **Staging copy (cp -a)** | No | Any | O(workdir size) | Instant (rm staging) | Easy (rsync --delete) |
| **OverlayFS** | No (Linux 5.11+) | Any | Instant | Instant (rm upper) | Medium (rsync upper + whiteouts) |
| **fuse-overlayfs** | No | Any + FUSE | Instant | Instant | Medium |
| **Btrfs snapshots** | Yes | Btrfs only | Instant (CoW) | Instant | Easy (mv) |
| **ZFS snapshots** | Yes | ZFS only | Instant (CoW) | Instant | Easy (rollback) |
| **Git stash/worktree** | No | Any (needs git) | Slow (large repos) | Fast (git restore) | Easy (git) |

## Current implementation: staging copy

We use a **staging copy** approach because overlayfs and fuse-overlayfs do not work
reliably inside bwrap's user namespace on common configurations:

- **Kernel overlayfs**: Requires UID 0 inside the user namespace, but bwrap runs as
  `--uid 1000` which drops all capabilities including `CAP_SYS_ADMIN`.
- **fuse-overlayfs**: Requires `fusermount3` which needs `CAP_SYS_ADMIN` to call
  `mount(2)`. Even with `--cap-add CAP_SYS_ADMIN`, `fusermount3` fails because the
  setuid mechanism doesn't work in user namespaces.
- **bwrap native overlay (`--overlay`)**: Available in bwrap 0.10+, but not yet
  widely deployed (Ubuntu 24.04 ships bwrap 0.9.0).

### Architecture

```
Host
  +-- $WORKDIR (original, untouched)
  +-- $SNAPSHOT_STAGING (cp -a copy, rw by sandbox)

Sandbox
  +-- /workspace --> bind $SNAPSHOT_STAGING (rw)
```

### Workflow

```bash
# Before sandbox launch:
SNAPSHOT_STAGING=$(umask 077; mktemp -d "${WORKDIR%/*}/.claudebox-snapshot-XXXXXX")
cp -a --no-preserve=ownership "$WORKDIR/." "$SNAPSHOT_STAGING/"

# Save workdir fingerprint for concurrent modification detection:
find "$WORKDIR" -printf '%P %T@ %s\n' | sort > "$SNAPSHOT_STAGING/.claudebox-manifest"

# bwrap bind:
--bind "$SNAPSHOT_STAGING" /workspace    # sandbox writes to staging copy

# After sandbox exits:
diff -rq "$WORKDIR" "$SNAPSHOT_STAGING" --exclude='.claudebox-manifest'

# Detect concurrent modifications:
find "$WORKDIR" -printf '%P %T@ %s\n' | sort | diff - "$SNAPSHOT_STAGING/.claudebox-manifest"

# Apply changes (with hardlink preservation):
rsync -aH --delete "$SNAPSHOT_STAGING/" "$WORKDIR/"

# Rollback (original untouched):
rm -rf "$SNAPSHOT_STAGING"
```

### Trade-offs

**Pros**:
- Works on any Linux, any filesystem, no root, no FUSE, no special kernel config
- Simple implementation, easy to debug
- Staging dir on same filesystem = fast cp and no cross-device issues

**Cons**:
- Snapshot creation time proportional to workdir size (cp -a)
- Doubles disk usage during sandbox execution
- Not suitable for very large workdirs (> 10 GB)

### Security hardening

- **Umask enforcement**: `umask 077` before `mktemp` prevents TOCTOU permission window
- **No ownership preservation**: `--no-preserve=ownership` avoids `cp` failures on
  files owned by other users
- **Concurrent modification detection**: A manifest file (`find -printf '%P %T@ %s'`)
  is saved at snapshot time and compared before merge. If the workdir was modified
  during the session, a warning is shown
- **Merge failure recovery**: If `rsync` fails mid-merge, the staging directory is
  preserved with recovery instructions instead of being deleted
- **Signal safety**: During the merge prompt phase, Ctrl-C preserves the staging
  directory (with its path printed) instead of deleting it. During copy or sandbox
  phases, staging is cleaned up normally
- **Hardlink preservation**: `rsync -aH` preserves hardlinks on merge

### Performance

For typical source code repositories:
- < 100 MB: near-instant (< 1 second)
- 100 MB - 1 GB: 1-10 seconds
- 1 GB - 10 GB: 10-60 seconds (consider git worktree instead)

## Future: overlayfs when bwrap supports it

bwrap 0.10+ adds native `--overlay` / `--overlay-src` / `--tmp-overlay` options
that handle overlayfs setup before entering the sandbox. When widely available,
the implementation can switch to:

```bash
# bwrap 0.10+ native overlay:
BWRAP+=(
  --overlay-src "$WORKDIR"
  --overlay "$OVERLAY_DIR/upper" "$OVERLAY_DIR/work" /workspace
)
```

This would give instant snapshots (no copy), zero extra disk usage (CoW), and
instant rollback (rm upper). The post-exit merge logic would need to handle
overlayfs whiteout files (character devices with major:minor 0:0) for deletions.

## Alternatives considered

### OverlayFS (kernel, in user namespace)
Tested on Linux 6.8 with bwrap 0.9. Failed because:
1. `mount -t overlay` requires UID 0 inside the namespace
2. bwrap's `--uid 1000` drops capabilities
3. Even with `--cap-add CAP_SYS_ADMIN`, the process is UID 1000 (not root)

### fuse-overlayfs
Tested with fuse-overlayfs 1.5. Failed because:
1. `fusermount3` needs `CAP_SYS_ADMIN` for the `mount(2)` syscall
2. setuid on fusermount3 is ignored in user namespaces
3. `/dev/fuse` is accessible but the mount call is denied

### Btrfs / ZFS snapshots
Fast CoW snapshots but require specific filesystems and root privileges.
Not portable across different host setups.

### Git stash/worktree
Works anywhere git is available. Only tracks git-managed files, misses untracked
files unless explicitly added. Good optimization when workdir is a git repo.
