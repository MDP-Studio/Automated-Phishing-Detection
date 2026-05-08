# Remote Sync After Push

This repo has a remote runtime checkout. After an agent commits and pushes a
verified change from the local Windows repo, the agent must also pull that
commit on the remote checkout before saying the work is done.

## Required Step

Run this after a successful `git push`:

```bash
ssh meidie@100.110.79.52 "cd /home/meidie/.openclaw/workspace/Automated-Phishing-Detection && git pull --ff-only"
```

Then verify the remote checkout is at the pushed commit:

```bash
ssh meidie@100.110.79.52 "cd /home/meidie/.openclaw/workspace/Automated-Phishing-Detection && git status --short --branch && git rev-parse --short HEAD"
```

## If The Change Affects The Running App

For code, dependency, Docker, environment, migration, frontend, route, or
runtime behavior changes, follow the pull with the project deploy script:

```bash
ssh meidie@100.110.79.52 "cd /home/meidie/.openclaw/workspace/Automated-Phishing-Detection && bash scripts/docker_deploy.sh"
```

Do not print `.env` values, container environment values, signing keys, API
keys, mailbox credentials, Stripe secrets, or analyst tokens while checking the
remote.

## Blockers To Report

Report the exact blocker if the remote pull cannot be completed:

- SSH is unavailable or authentication fails.
- The remote working tree has local changes that prevent a fast-forward pull.
- The remote branch is not tracking the same GitHub branch.
- `git pull --ff-only` fails.
- The deploy script fails after a runtime-affecting change.

Do not hide a failed remote pull behind a successful local push. Local push plus
remote pull is the expected delivery state for this project.
