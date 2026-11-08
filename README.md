# quaq-tool-001-02-ci-workflows

The shared CI pipelines of QuantalQ: composite actions and reusable GitHub workflows that the
repositories of the organisation call instead of keeping their own copy. A consumer pins this
repository by **full commit SHA**, with the release tag as a comment, so a change here reaches a
repository only when that repository moves its pin.

| Pipeline | Paths | Decision |
|---|---|---|
| Dependency vulnerability scan | `image-gate/`, `trivy-image/`, `scripts/`, `trivy.yaml`, `trivy-version`, `.github/workflows/release-image-scan.yml` | ORG-BE-ADR-0015 |

## Dependency vulnerability scan

The shared dependency vulnerability scan of QuantalQ backends: it scans **built container
images** with [Trivy](https://trivy.dev) and gives the same verdict in CI and on a developer's
machine. It is the implementation of the organisation's backend decision ORG-BE-ADR-0015.

| Finding | Verdict |
|---|---|
| HIGH or CRITICAL (CVSS ≥ 7.0) in an **application library** of a scanned image | **blocks**, with or without a fixed version, unless an exception covers it |
| Operating-system packages of the base image | reported, never blocks |
| MEDIUM, LOW, no severity | not gated |

Each consuming repository scans its **shipped images** and its **test images** (the images CI
builds to run the test suites), keeps its exceptions in `.trivyignore.yaml` at the repository
root, and pins this repository by full commit SHA.

### Contents

| Path | What it is |
|---|---|
| `image-gate/` | Composite action: the merge gate for one or more built images |
| `scripts/vuln-scan.sh` | The scan itself; the action, the weekly workflow and the local command all run it |
| `scripts/check_exceptions.py` | The exception-entry check that runs before every scan |
| `trivy.yaml`, `trivy-version` | The shared Trivy settings and the pinned Trivy version |
| `.github/workflows/release-image-scan.yml` | Reusable workflow: weekly scan of the current release images |
| `trivy-image/` | Composite action: a single Trivy run with the shared version and settings (e.g. an SBOM) |

`vuln-scan.sh` runs `aquasec/trivy` at the version in `trivy-version` as a container, and moves
its files into the containers with `docker cp` rather than bind mounts, so it works wherever a
Docker CLI reaches a daemon, also from inside a container.

Exit codes: **0** no blocking finding, **1** a blocking finding or an invalid exception file,
**2** no verdict (the scanner or the check could not run). A broken run never passes.

### Merge gate

A job in the pull-request workflow of the integration branch builds the images and runs the
gate. Its name is the required status check.

```yaml
  dependency-vulnerability-gate:
    name: Dependency Vulnerability Gate
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<sha> # v7.0.1
        with:
          persist-credentials: false
      - name: Build the shipped and test images
        run: |
          docker build --pull -f docker/prod/Dockerfile -t product:scan .
          docker build -f docker/dev/Dockerfile -t product-test:scan .
      - uses: QuantalQ/quaq-tool-001-02-ci-workflows/image-gate@<full sha> # vX.Y.Z
        with:
          images: |
            product:scan
            product-test:scan
```

Blocking findings and reported base-image findings are written to the run summary; the full
reports are kept as an artefact.

### Weekly release-image scan

On the default branch:

```yaml
on:
  schedule:
    - cron: '17 6 * * 1'
  workflow_dispatch:
permissions:
  contents: read
  packages: read
jobs:
  scan:
    uses: QuantalQ/quaq-tool-001-02-ci-workflows/.github/workflows/release-image-scan.yml@<full sha> # vX.Y.Z
    with:
      images: |
        ghcr.io/org/product:latest
```

It blocks nothing. The run is red while a release image has a blocking-class finding, so that
GitHub notifies, and green again once the image is updated.

### Exceptions

`.trivyignore.yaml` at the repository root is Trivy's own ignore file. Every entry needs an
`id`, a non-empty `statement` and an `expired_at` date; otherwise the scan stops before scanning
anything. After `expired_at` Trivy no longer applies the entry and the finding blocks again.

```yaml
vulnerabilities:
  - id: CVE-2026-00000
    paths:
      - "usr/local/lib/python3.13/site-packages/example-1.0.0.dist-info/METADATA"
    statement: Why this finding does not apply, or what is waited for.
    expired_at: 2027-01-31
```

### Local command

The local command scans locally built images with the same Trivy, settings and exception file.
It takes the pin from the repository's own workflow files, so there is exactly one pin, and
fails when the workflows reference this repository at no SHA or at more than one.

```make
VULN_SCAN_REPO := QuantalQ/quaq-tool-001-02-ci-workflows
VULN_SCAN_IMAGES := product:scan product-test:scan

vuln-scan: ## scan the shipped and test images like the merge gate
	docker build --pull -f docker/prod/Dockerfile -t product:scan .
	docker build -f docker/dev/Dockerfile -t product-test:scan .
	@pins=$$(grep -rhoE '$(VULN_SCAN_REPO)/[^@[:space:]]+@[0-9a-f]{40}' .github/workflows | sed 's/.*@//' | sort -u); \
	count=$$(printf '%s' "$$pins" | grep -c .); \
	if [ "$$count" -ne 1 ]; then \
	  echo "vuln-scan: the workflows pin $(VULN_SCAN_REPO) at $$count SHAs, expected exactly one: $$pins" >&2; exit 2; \
	fi; \
	dir="$${XDG_CACHE_HOME:-$$HOME/.cache}/quaq-vulnerability-scan/$$pins"; \
	if [ ! -f "$$dir/scripts/vuln-scan.sh" ]; then \
	  rm -rf "$$dir" && mkdir -p "$$dir" && \
	  curl -fsSL "https://codeload.github.com/$(VULN_SCAN_REPO)/tar.gz/$$pins" | tar -xz -C "$$dir" --strip-components=1; \
	fi; \
	sh "$$dir/scripts/vuln-scan.sh" --repo . $(VULN_SCAN_IMAGES)
```

Environment variables of `vuln-scan.sh`:

| Variable | Default | Meaning |
|---|---|---|
| `VULN_SCAN_DOCKER_SOCKET` | `/var/run/docker.sock` | The daemon's socket as the daemon host sees it |
| `VULN_SCAN_CACHE_VOLUME` | `quaq-vulnerability-scan-trivy-cache` | Volume that keeps Trivy's database between runs |

### Updating

Dependabot's `github-actions` ecosystem in a consuming repository proposes the SHA of a new
release; a change of the settings therefore reaches a product as a reviewed pull request. Releases
are made with the `Release` workflow from `develop`.

## License

Apache License 2.0, see `LICENSE` and `NOTICE`.
