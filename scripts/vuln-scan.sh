#!/bin/sh
# The shared scan of the dependency vulnerability gate (ORG-BE-ADR-0015), the same in CI and locally.
#
# Usage: vuln-scan.sh [--repo DIR] [--report-dir DIR] IMAGE...
#
# For every image, already present in the Docker daemon, it scans the application libraries with the
# shared trivy.yaml and the repository's .trivyignore.yaml (a HIGH or CRITICAL finding blocks), and the
# base image's operating-system packages (reported, never blocking). Before any scan it checks the
# entries of the exception file, so an invalid file never silently weakens a verdict.
#
# Exit code 0: no blocking finding. 1: a blocking finding, or an invalid exception file.
# 2: no verdict, because the scanner or the check could not run; a broken run never passes.
#
# Trivy and the check run as containers, and files reach them through `docker cp`, not bind mounts,
# so the script also works when the Docker CLI runs in a container next to the daemon. Environment:
#   VULN_SCAN_DOCKER_SOCKET   the daemon's socket as the daemon host sees it (default /var/run/docker.sock)
#   VULN_SCAN_CACHE_VOLUME    the volume that keeps Trivy's database between runs

set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)
TRIVY_IMAGE="aquasec/trivy:$(cat "$HERE/trivy-version")"
PYTHON_IMAGE="python:3.13-slim"
PYYAML_VERSION="6.0.2"
DOCKER_SOCKET="${VULN_SCAN_DOCKER_SOCKET:-/var/run/docker.sock}"
CACHE_VOLUME="${VULN_SCAN_CACHE_VOLUME:-quaq-vulnerability-scan-trivy-cache}"
# Trivy's exit code for a finding; any other non-zero code is a scanner failure.
FINDING_EXIT=3

REPO_DIR=.
REPORT_DIR=vulnerability-reports

usage() {
    echo "usage: vuln-scan.sh [--repo DIR] [--report-dir DIR] IMAGE..." >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --repo) [ $# -ge 2 ] || usage; REPO_DIR=$2; shift 2 ;;
        --report-dir) [ $# -ge 2 ] || usage; REPORT_DIR=$2; shift 2 ;;
        --) shift; break ;;
        -*) usage ;;
        *) break ;;
    esac
done
[ $# -ge 1 ] || usage

IGNORE_FILE="$REPO_DIR/.trivyignore.yaml"
mkdir -p "$REPORT_DIR"

annotate() { # level message
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::$1::$2"
    else
        echo "$1: $2" >&2
    fi
}

summary() { # appends a line to the run summary in CI
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
    fi
}

summary_report() { # title file
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
    {
        echo "### $1"
        echo '```'
        head -c 200000 "$2"
        echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
}

# Copies a file into a created container; a file that cannot be copied removes the container, so no
# scan runs without its configuration or its exceptions.
copy_in() { # container-id source destination
    if ! docker cp "$2" "$1:$3" > /dev/null; then
        docker rm -f "$1" > /dev/null 2>&1 || true
        return 2
    fi
}

# Runs a created container to its end, with stdout to a file, and removes it. Prints the exit code.
run_created() { # container-id stdout-file
    rc=0
    docker start -a "$1" > "$2" || rc=$?
    docker rm -f "$1" > /dev/null 2>&1 || true
    echo "$rc"
}

check_exceptions() {
    cid=$(docker create -e PIP_DISABLE_PIP_VERSION_CHECK=1 "$PYTHON_IMAGE" sh -c \
        "pip install --quiet --root-user-action=ignore pyyaml==$PYYAML_VERSION >&2 \
         && python /tmp/check_exceptions.py /tmp/.trivyignore.yaml .trivyignore.yaml") || return 2
    copy_in "$cid" "$HERE/scripts/check_exceptions.py" /tmp/check_exceptions.py || return 2
    if [ -f "$IGNORE_FILE" ]; then
        copy_in "$cid" "$IGNORE_FILE" /tmp/.trivyignore.yaml || return 2
    fi
    rc=$(run_created "$cid" "$REPORT_DIR/exception-check.txt")
    cat "$REPORT_DIR/exception-check.txt"
    return "$rc"
}

scan() { # image package-types report-file; returns Trivy's exit code
    cid=$(docker create \
        -v "$DOCKER_SOCKET:/var/run/docker.sock" \
        -v "$CACHE_VOLUME:/root/.cache/trivy" \
        "$TRIVY_IMAGE" image \
        --config /tmp/trivy.yaml \
        --ignorefile /tmp/.trivyignore.yaml \
        --pkg-types "$2" \
        --exit-code "$FINDING_EXIT" \
        --image-src docker \
        --no-progress \
        "$1") || return 2
    copy_in "$cid" "$HERE/trivy.yaml" /tmp/trivy.yaml || return 2
    copy_in "$cid" "$SCAN_IGNORE_FILE" /tmp/.trivyignore.yaml || return 2
    return "$(run_created "$cid" "$3")"
}

rc=0
check_exceptions || rc=$?
if [ "$rc" -ne 0 ]; then
    if [ "$rc" -eq 1 ]; then
        annotate error ".trivyignore.yaml is not a valid exception file, see above; no image is scanned with it."
        summary "**Dependency vulnerability gate: invalid exception file, no scan ran.**"
        exit 1
    fi
    annotate error "The exception check could not run (exit code $rc)."
    exit 2
fi

# Trivy refuses an ignore file that does not exist, so a repository without exceptions is scanned
# with an empty one.
if [ -f "$IGNORE_FILE" ]; then
    SCAN_IGNORE_FILE=$IGNORE_FILE
else
    SCAN_IGNORE_FILE="$REPORT_DIR/no-exceptions.trivyignore.yaml"
    printf 'vulnerabilities: []\n' > "$SCAN_IGNORE_FILE"
fi

blocked=0
broken=0
for image in "$@"; do
    slug=$(printf '%s' "$image" | tr -c 'A-Za-z0-9._-' '_')
    libraries="$REPORT_DIR/$slug-libraries.txt"
    base="$REPORT_DIR/$slug-base-image.txt"

    echo "== $image: application libraries (HIGH and CRITICAL block)"
    rc=0
    scan "$image" library "$libraries" || rc=$?
    cat "$libraries"
    case "$rc" in
        0) summary "- \`$image\`: application libraries, no blocking finding" ;;
        "$FINDING_EXIT")
            blocked=1
            annotate error "$image has HIGH or CRITICAL vulnerabilities in its application libraries; they block the merge."
            summary_report "BLOCKING: application libraries of $image" "$libraries" ;;
        *)
            broken=1
            annotate error "The library scan of $image failed (exit code $rc); there is no verdict." ;;
    esac

    echo "== $image: base image operating-system packages (reported, not blocking)"
    rc=0
    scan "$image" os "$base" || rc=$?
    cat "$base"
    case "$rc" in
        0) ;;
        "$FINDING_EXIT")
            annotate warning "The base image of $image has HIGH or CRITICAL vulnerabilities its publisher has not fixed yet. They do not block."
            summary_report "Reported, not blocking: base image of $image" "$base" ;;
        *)
            broken=1
            annotate error "The base image scan of $image failed (exit code $rc); there is no verdict." ;;
    esac
done

if [ "$broken" -ne 0 ]; then
    echo "Dependency vulnerability gate: NO VERDICT, a scan failed."
    exit 2
fi
if [ "$blocked" -ne 0 ]; then
    echo "Dependency vulnerability gate: BLOCKED by HIGH or CRITICAL findings in application libraries."
    echo "Update the library, or add an expiring entry with a statement to .trivyignore.yaml."
    exit 1
fi
echo "Dependency vulnerability gate: PASSED."
