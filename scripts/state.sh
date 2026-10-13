#!/usr/bin/env bash
# Durable state for scheduled runners (CI has no persistent disk).
#
#   scripts/state.sh pull|push
#
# Backends (STATE_BACKEND):
#   git-branch (default)  force-pushes a single-commit orphan branch `bd-svm-state`
#                         containing state.db. Needs push rights. NOTE: the DB
#                         holds component names and Black Duck URLs - use a
#                         private repo.
#   s3                    aws s3 cp to $STATE_S3_URI (e.g. s3://bucket/bd-svm/state.db)
#   none                  do nothing
set -euo pipefail

BACKEND="${STATE_BACKEND:-git-branch}"
DB="${STATE_DB:-data/state.db}"
BRANCH="${STATE_BRANCH:-bd-svm-state}"
action="${1:?usage: state.sh pull|push}"

case "$BACKEND" in
  none) exit 0 ;;
  git-branch)
    case "$action" in
      pull)
        mkdir -p "$(dirname "$DB")"
        if git fetch --quiet origin "$BRANCH:refs/remotes/origin/$BRANCH" 2>/dev/null; then
          git show "origin/$BRANCH:state.db" > "$DB"
          echo "state: restored $DB from origin/$BRANCH"
        else
          echo "state: no '$BRANCH' branch yet - starting fresh"
        fi ;;
      push)
        [ -f "$DB" ] || { echo "state: $DB missing, nothing to push"; exit 0; }
        # Plumbing only: no checkout/working tree changes, uses existing credentials.
        blob=$(git hash-object -w "$DB")
        tree=$(printf '100644 blob %s\tstate.db\n' "$blob" | git mktree)
        commit=$(git -c user.name="bd-svm-state" -c user.email="bd-svm-state@users.noreply.github.com" \
                 commit-tree "$tree" -m "state $(date -u +%Y-%m-%dT%H:%M:%SZ)")
        git push --quiet --force origin "$commit:refs/heads/$BRANCH"
        echo "state: pushed $DB to origin/$BRANCH" ;;
      *) echo "unknown action $action"; exit 2 ;;
    esac ;;
  s3)
    : "${STATE_S3_URI:?set STATE_S3_URI=s3://bucket/key}"
    case "$action" in
      pull) mkdir -p "$(dirname "$DB")"
            aws s3 cp --quiet "$STATE_S3_URI" "$DB" 2>/dev/null && echo "state: restored from $STATE_S3_URI" \
              || echo "state: no object yet - starting fresh" ;;
      push) [ -f "$DB" ] && aws s3 cp --quiet "$DB" "$STATE_S3_URI" && echo "state: pushed to $STATE_S3_URI" || true ;;
      *) echo "unknown action $action"; exit 2 ;;
    esac ;;
  *) echo "unknown STATE_BACKEND=$BACKEND"; exit 2 ;;
esac
