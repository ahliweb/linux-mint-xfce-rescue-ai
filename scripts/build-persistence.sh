#!/usr/bin/env bash
# Build a Ventoy persistence image (ext4, label casper-rw) that contains a
# Linux Mint 22.3 live overlay with Hermes and the rescue toolkit pre-installed.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
#
# Nothing here touches a block device. Docker is used as an unprivileged-host
# sandbox: the Mint root filesystem is imported as a throwaway image, the
# install runs in a container, and the container's diff (the overlayfs upper
# layer) is written into a plain file with mkfs.ext4 -d.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")/.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/rescue-env.sh
source "$root/scripts/lib/rescue-env.sh"

usage() {
  cat >&2 <<EOF
usage: $0 --iso VERIFIED_ISO --output FILE.dat [--size-mib N] [--env-file FILE | --no-provision-secrets]
          [--installer-sha256 HEX] [--skip-hermes-install] [--keep-work]

  --iso FILE               Linux Mint ISO that was already GPG+SHA256 verified (read-only use)
  --output FILE.dat        image to create (must not exist; written 0600)
  --size-mib N             image size in MiB (default 8192, minimum 4096)
  --env-file FILE          dotenv file to read ONLY OPENCODE_GO_API_KEY from (default: $root/.env)
  --no-provision-secrets   build without an API key (the image is then credential-free)
  --installer-sha256 HEX   pin the Hermes installer (or set HERMES_INSTALLER_SHA256)
  --skip-hermes-install    do not install Hermes (rescue bundle and profile only)
  --keep-work              keep the work directory, containers and images for inspection
EOF
}

iso=''
output=''
size_mib=8192
env_file="$root/.env"
env_file_explicit=0
provision_secrets=1
installer_sha256=${HERMES_INSTALLER_SHA256:-}
skip_hermes=0
keep_work=0
while (($#)); do
  case "$1" in
    --iso) iso=${2:?missing ISO path}; shift 2 ;;
    --output) output=${2:?missing output path}; shift 2 ;;
    --size-mib) size_mib=${2:?missing size in MiB}; shift 2 ;;
    --env-file) env_file=${2:?missing dotenv file}; env_file_explicit=1; shift 2 ;;
    --no-provision-secrets) provision_secrets=0; shift ;;
    --installer-sha256) installer_sha256=${2:?missing SHA-256 hex digest}; shift 2 ;;
    --skip-hermes-install) skip_hermes=1; shift ;;
    --keep-work) keep_work=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[[ -n $iso && -n $output ]] || { usage; exit 2; }
[[ $size_mib =~ ^[0-9]+$ ]] || { printf 'Invalid --size-mib (integer required): %s\n' "$size_mib" >&2; exit 2; }
((size_mib >= 4096)) || { printf '--size-mib must be at least 4096 (got %s).\n' "$size_mib" >&2; exit 2; }
((size_mib <= 1048576)) || { printf '--size-mib is unreasonably large: %s\n' "$size_mib" >&2; exit 2; }
if [[ -n $installer_sha256 && ! $installer_sha256 =~ ^[0-9a-fA-F]{64}$ ]]; then
  printf 'Invalid installer SHA-256 (expected 64 hex characters).\n' >&2
  exit 2
fi
if ((!provision_secrets)) && ((env_file_explicit)); then
  printf '%s\n' '--env-file and --no-provision-secrets are mutually exclusive.' >&2
  exit 2
fi
[[ -f $iso ]] || { printf 'ISO not found: %s\n' "$iso" >&2; exit 1; }
case $output in *$'\n'*) printf 'Output path must not contain a newline.\n' >&2; exit 2 ;; esac
if [[ -e $output || -L $output ]]; then
  printf 'Refusing: output already exists: %s\n' "$output" >&2
  exit 1
fi
output=$(realpath -m -- "$output")
out_dir=$(dirname -- "$output")
[[ -d $out_dir && -w $out_dir ]] || { printf 'Output directory is not a writable directory: %s\n' "$out_dir" >&2; exit 1; }

# Read only the allowlisted key, as data (never `source`), before any heavy work.
api_key=''
if ((provision_secrets)); then
  [[ -f $env_file ]] || {
    if ((env_file_explicit)); then printf 'Explicit dotenv file not found: %s\n' "$env_file" >&2
    else printf 'Default dotenv file not found: %s; use --no-provision-secrets to build without an API key.\n' "$env_file" >&2; fi
    exit 1
  }
  unset OPENCODE_GO_API_KEY
  rescue_load_env "$env_file" || exit 1
  api_key=${OPENCODE_GO_API_KEY:-}
  unset OPENCODE_GO_API_KEY
  [[ -n $api_key ]] || { printf '%s does not contain a non-empty OPENCODE_GO_API_KEY.\n' "$env_file" >&2; exit 1; }
  case $api_key in *$'\n'* | *$'\r'*)
    printf 'OPENCODE_GO_API_KEY must not contain newlines; refusing.\n' >&2
    exit 2 ;;
  esac
fi

for tool in docker python3 sha256sum e2fsck; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'Required tool not found: %s\n' "$tool" >&2; exit 1; }
done
if ! { command -v 7z >/dev/null 2>&1 || command -v xorriso >/dev/null 2>&1; }; then
  printf 'Required: 7z or xorriso (to read casper/filesystem.squashfs from the ISO).\n' >&2
  exit 1
fi
docker info >/dev/null 2>&1 || { printf 'Cannot talk to the Docker daemon (is the user in the docker group?).\n' >&2; exit 1; }

started=$(date +%s)
log() { printf '==> %s\n' "$*"; }

iso_sha=$(sha256sum -- "$iso"); iso_sha=${iso_sha%% *}
tag=${iso_sha:0:12}
base_tag="rescue-omes/mint-live-base:$tag"
built_tag="rescue-omes/mint-live-built:$tag"
suffix=$$
build_ctr="rescue-omes-build-$suffix"
image_ctr="rescue-omes-image-$suffix"
work=$(mktemp -d "$out_dir/.build-persistence.XXXXXX")
chmod 0700 "$work"
base_created=0
output_created=0
success=0

cleanup() {
  local rc=$?
  rm -f -- "$work/secret/hermes-env" 2>/dev/null || true
  if ((keep_work)); then
    printf 'Keeping work directory %s, containers (%s %s) and images (%s %s).\n' \
      "$work" "$build_ctr" "$image_ctr" "$base_tag" "$built_tag" >&2
  else
    docker rm -f "$build_ctr" "$image_ctr" >/dev/null 2>&1 || true
    docker rmi -f "$built_tag" >/dev/null 2>&1 || true
    if ((base_created)); then docker rmi -f "$base_tag" >/dev/null 2>&1 || true; fi
    chmod -R u+rwX -- "$work" 2>/dev/null || true
    rm -rf -- "$work"
  fi
  if ((!success && output_created)); then rm -f -- "$output"; fi
  ((success)) || printf 'build-persistence.sh FAILED (exit %s); no image was produced.\n' "$rc" >&2
  return "$rc"
}
trap cleanup EXIT

# (a) casper/filesystem.squashfs from the ISO, read-only.
log 'extracting casper/filesystem.squashfs from the ISO'
if command -v 7z >/dev/null 2>&1; then
  7z e -y -bso0 -bsp0 -o"$work" "$iso" casper/filesystem.squashfs
else
  xorriso -osirrox on -indev "$iso" -extract /casper/filesystem.squashfs "$work/filesystem.squashfs" >/dev/null
fi
[[ -s $work/filesystem.squashfs ]] || { printf 'casper/filesystem.squashfs not found in %s\n' "$iso" >&2; exit 1; }

# (b) squashfs -> throwaway docker base image. Devices/ownership need root, so
# either fakeroot on the host or a root container is used; the tar is streamed.
if docker image inspect "$base_tag" >/dev/null 2>&1; then
  log "reusing existing base image $base_tag"
else
  log "importing the Mint root filesystem as $base_tag"
  if command -v unsquashfs >/dev/null 2>&1 && command -v fakeroot >/dev/null 2>&1; then
    # shellcheck disable=SC2016  # $1/$2 belong to the inner bash, not this shell
    fakeroot -- bash -c '
      set -o pipefail
      trap "rm -rf -- \"$2\"" EXIT
      unsquashfs -no-xattrs -no-progress -q -d "$2" "$1" >/dev/null &&
        tar --numeric-owner -C "$2" -cf - .
    ' _ "$work/filesystem.squashfs" "$work/rootfs" | docker import - "$base_tag" >/dev/null
  else
    log 'unsquashfs/fakeroot not on the host: unpacking inside an alpine container'
    docker run --rm -v "$work:/w:ro" alpine:latest sh -c \
      'apk add -q --no-progress squashfs-tools >/dev/null && unsquashfs -no-xattrs -no-progress -q -d /r /w/filesystem.squashfs >/dev/null && tar --numeric-owner -C /r -cf - .' \
      | docker import - "$base_tag" >/dev/null
  fi
  base_created=1
fi
rm -f -- "$work/filesystem.squashfs"
base_layers=$(docker image inspect --format '{{len .RootFS.Layers}}' "$base_tag")

# Allowlisted rescue bundle (never .env, rescue.env, .git, ISOs, images).
log 'staging the allowlisted rescue bundle'
"$root/scripts/prepare-ventoy-usb.sh" --bundle-only "$work/rescue-src" >/dev/null

# (c) Build container: network enabled for apt and the Hermes installer only.
log 'running the install inside the build container (network: apt + Hermes installer)'
docker run -d --name "$build_ctr" --hostname rescue-omes-build "$base_tag" sleep infinity >/dev/null
docker cp "$work/rescue-src" "$build_ctr:/opt/rescue-src"
docker cp "$root/scripts/lib/persistence-container-build.sh" "$build_ctr:/opt/persistence-container-build.sh"
docker exec -e "SKIP_HERMES=$skip_hermes" -e "HERMES_INSTALLER_SHA256=$installer_sha256" \
  "$build_ctr" bash /opt/persistence-container-build.sh

# (e) The container's diff is the overlayfs upper layer. docker commit +
# docker save gives the top layer as a tar with AUFS-style whiteouts.
log 'committing the container and extracting its top layer'
docker commit "$build_ctr" "$built_tag" >/dev/null
docker rm -f "$build_ctr" >/dev/null
built_layers=$(docker image inspect --format '{{len .RootFS.Layers}}' "$built_tag")
((built_layers == base_layers + 1)) || {
  printf 'Unexpected layer count after commit: base=%s built=%s\n' "$base_layers" "$built_layers" >&2
  exit 1
}
docker save -o "$work/built.tar" "$built_tag"
python3 - "$work/built.tar" "$work/layer.tar" "$built_layers" <<'PY'
import json
import shutil
import sys
import tarfile

saved, dest, expected = sys.argv[1], sys.argv[2], int(sys.argv[3])
with tarfile.open(saved) as tar:
    manifest = json.load(tar.extractfile("manifest.json"))
    layers = manifest[0]["Layers"]
    if len(layers) != expected:
        raise SystemExit(f"manifest lists {len(layers)} layers, expected {expected}")
    with tar.extractfile(layers[-1]) as src, open(dest, "wb") as out:
        shutil.copyfileobj(src, out, 1 << 20)
PY
rm -f -- "$work/built.tar"

log 'converting whiteouts and filtering the layer'
python3 "$root/scripts/lib/overlay_whiteouts.py" convert "$work/layer.tar" "$work/filtered.tar" "$work/plan.json"
((keep_work)) || rm -f -- "$work/layer.tar"

# (d)+(e) Helper container without network: stage upper/ + work/, optional
# secret, mkfs.ext4 -d, opaque xattrs via debugfs, e2fsck.
log 'building the ext4 image in a network-less helper container'
mkdir -p "$work/out"
docker run -d --name "$image_ctr" --network none -v "$work/out:/out" "$base_tag" sleep infinity >/dev/null
docker exec "$image_ctr" mkdir -p /in
docker cp "$work/filtered.tar" "$image_ctr:/in/layer.tar"
docker cp "$work/plan.json" "$image_ctr:/in/plan.json"
docker cp "$root/scripts/lib/overlay_whiteouts.py" "$image_ctr:/in/overlay_whiteouts.py"
docker cp "$root/scripts/lib/persistence-container-image.sh" "$image_ctr:/in/persistence-container-image.sh"
((keep_work)) || rm -f -- "$work/filtered.tar"
if ((provision_secrets)); then
  mkdir -m 0700 "$work/secret"
  (
    umask 077
    # printf is a shell builtin: the key never appears in any process argv.
    printf 'HERMES_HOME=%s\nOPENCODE_GO_API_KEY=%s\n' \
      "$(rescue_sh_squote /home/mint/.local/share/rescue-omes/hermes)" \
      "$(rescue_sh_squote "$api_key")" > "$work/secret/hermes-env"
  )
  api_key=''
  docker cp "$work/secret/hermes-env" "$image_ctr:/in/hermes-env"
  rm -f -- "$work/secret/hermes-env"
  log 'secret staged for provisioning (credential-bearing image)'
fi
docker exec "$image_ctr" bash /in/persistence-container-image.sh "$size_mib"

[[ -s $work/out/casper-rw.img ]] || { printf 'The helper container produced no image.\n' >&2; exit 1; }
# Write the final file 0600, sparse, never overwriting an existing output.
(
  umask 077
  set -o noclobber
  : > "$output"
)
output_created=1
cp --sparse=always -- "$work/out/casper-rw.img" "$output"
chmod 0600 -- "$output"
rm -f -- "$work/out/casper-rw.img"

# (f) Independent read-only check on the host, then report.
log 'e2fsck -fn on the final image (read-only)'
e2fsck -fn "$output"
sum=$(sha256sum -- "$output"); sum=${sum%% *}
success=1
printf '\nPersistence image: %s\n' "$output"
printf 'Size (apparent): %s bytes (%s MiB)   On disk: %s\n' "$(stat -c %s -- "$output")" "$size_mib" "$(du -h -- "$output" | cut -f1)"
printf 'SHA-256: %s\n' "$sum"
if ((provision_secrets)); then
  printf 'WARNING: this image is CREDENTIAL-BEARING (OPENCODE_GO_API_KEY inside hermes/env). Use a private USB.\n'
else
  printf 'Credential-free image: enter OPENCODE_GO_API_KEY in the live session.\n'
fi
printf 'Build time: %s s. Boot with persistence is Hardware-required and NOT verified by this script.\n' "$(( $(date +%s) - started ))"
