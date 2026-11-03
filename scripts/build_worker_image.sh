#!/usr/bin/env bash
# Build the worker image from a clean, vendored build context and record its
# image ID for preflight / run metadata.
#
# Crates are vendored on the host (`cargo vendor --locked`, checksums verified
# against Cargo.lock) so the Rust stage builds fully offline.
set -euo pipefail
cd "$(dirname "$0")/.."
tag=${1:-argus-worker:dev}
ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT

cp Cargo.toml Cargo.lock "$ctx/"
cp -r crates "$ctx/crates"
find "$ctx/crates" -name target -type d -prune -exec rm -rf {} +
mkdir -p "$ctx/.cargo"
cargo vendor --locked --quiet "$ctx/vendor" > /dev/null
cat > "$ctx/.cargo/config.toml" <<'CFG'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
CFG
cp docker/Dockerfile.executor "$ctx/Dockerfile"

# Build-time only: on this host Docker's bridge network has no egress, so RUN
# steps use the host network to fetch signed Debian packages and pinned PyPI
# wheels. Workers themselves always run with `--network none`.
# Override with ARGUS_BUILD_NETWORK=default once bridge networking works.
docker build --network "${ARGUS_BUILD_NETWORK:-host}" -f "$ctx/Dockerfile" -t "$tag" "$ctx"
id=$(docker image inspect --format '{{.Id}}' "$tag")
printf '{"tag": "%s", "image_id": "%s"}\n' "$tag" "$id" > config/worker-image.lock
echo "built $tag $id"
