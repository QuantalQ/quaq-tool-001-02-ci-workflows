# Changelog

## Unreleased

- `image-gate` action and `scripts/vuln-scan.sh`: the shared scan of built images. HIGH and
  CRITICAL findings in application libraries block, also without a fixed version; the base
  image's operating-system packages are reported; exit code 0 pass, 1 blocked, 2 no verdict.
- `scripts/check_exceptions.py`: every entry of `.trivyignore.yaml` needs an `id`, a non-empty
  `statement` and a valid `expired_at`; an invalid file stops the scan before any image is scanned.
- `trivy.yaml` and `trivy-version`: the shared Trivy settings and the pinned Trivy version (0.70.0),
  read by CI and by the local command alike.
- `trivy-image` action: a single Trivy run with the shared version and settings, for example for a
  CycloneDX bill of materials.
- Reusable workflow `.github/workflows/release-image-scan.yml`: the weekly scan of the current
  release images, red while a release image has a blocking-class finding.
- Published under the Apache License 2.0.
