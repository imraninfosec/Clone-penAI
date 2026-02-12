# GitHub Real-Time Backup Setup

This project is configured for automated Git backup from `/opt/ai-pentest`.

## Included scripts

- `scripts/configure_github_remote.sh` - set/update remote URL
- `scripts/git_backup_once.sh` - commit and push once
- `scripts/git_backup_daemon.sh` - continuous auto-backup loop
- `scripts/start_git_backup_daemon.sh` - start daemon in background
- `scripts/stop_git_backup_daemon.sh` - stop daemon

## Quick start

1. Configure remote (already set to your repository URL by default):

```bash
/opt/ai-pentest/scripts/configure_github_remote.sh https://github.com/imraninfosec/AI-Pentest-Project.git
```

2. Configure token for unattended backup:

```bash
cp /opt/ai-pentest/.github-backup.env.example /opt/ai-pentest/.github-backup.env
# Edit the file and set GITHUB_TOKEN
```

3. Ensure GitHub authentication is available for this host (PAT or SSH).

4. Run first backup manually:

```bash
/opt/ai-pentest/scripts/git_backup_once.sh "initial backup"
```

5. Enable continuous backup:

```bash
/opt/ai-pentest/scripts/start_git_backup_daemon.sh
```

6. Check daemon log:

```bash
tail -f /opt/ai-pentest/logs/git-backup-daemon.log
```

## Notes

- Backup loop interval default is 20 seconds.
- Change interval by exporting `BACKUP_INTERVAL_SECONDS` before starting daemon.
- Generated runtime folders and very large binary/model assets are excluded in `.gitignore` to keep GitHub backup stable and pushable.
