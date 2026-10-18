# ModUpdater – keep NMS.py mods up to date from git while you play

An [NMS.py](https://github.com/monkeyman192/NMS.py) mod for No Man's Sky. Mods you installed as **git clones** in your
NMS.py mod folder update themselves: every few seconds ModUpdater fetches each clone's branch and, when there is
something new, brings the clone up to date. The changed mods then reload in the running game (AutoReload, included
here), and a mod file that is new in an update is loaded straight away.

- **Clean clone:** fast-forward to the new commits.
- **Local changes or a history of its own:** with "Overwrite local changes" on (the default), your local state is
  kept first (changed files in a git stash, local commits on a branch `mod_updater/backup-<time>`), then the clone is
  reset to the remote branch. With it off, that clone is skipped and the log says why.
- **Local commits the remote doesn't have yet** (your own unpushed work): left alone.

Settings (ModUpdater tab of the NMS.py window, saved to `mod_updater.json`):

| Setting | Default |
| --- | --- |
| Enabled | on |
| Check every (s) | 10 |
| Overwrite local changes (stashed first) | on |
| Branch | `main` (in the file) |

Needs Git for Windows. Private repositories need their own credentials in the clone, for example a read-only
deploy key: `git -C <clone> config core.sshCommand "ssh -i <key> -o IdentitiesOnly=yes"`.

AutoReload (`autoreload.py`) reloads any loaded mod whose file changed on disk, also when you edit a mod yourself.

Writes `mod_updater.log` next to `mod_updater.py`. License: MIT.
