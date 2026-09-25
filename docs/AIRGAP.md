# Air-gap operation

Stage 20 uses [compose.offline.yml](../infra/airgap/compose.offline.yml). It has
no frontend service, no public image registry references, an internal-only Docker
network, and `pull_policy: never` for each backend image.

Before deployment, load the two locally built image tags listed in
`infra/airgap/artifact-manifest.json` into the target Docker daemon. The manifest
also records the locally bundled schemas and the existing deterministic mapping
fallback, which has no network requirement.

Run `make test-airgap` to verify local artifact declarations plus onboarding,
parsing/validation, and passport generation with socket connections blocked. The
exporter suite remains part of this target and is exercised separately in Go.
