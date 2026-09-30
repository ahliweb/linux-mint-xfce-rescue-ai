#!/usr/bin/env bash
# Runs as root INSIDE a network-less helper container created by
# scripts/build-persistence.sh. It is never executed on the host.
# Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
#
# Turns the filtered container-layer tar into an ext4 image labelled
# "casper-rw" whose root holds upper/ (overlayfs upper layer) and work/.
#
# usage: persistence-container-image.sh SIZE_MIB
# Inputs:  /in/layer.tar /in/plan.json /in/overlay_whiteouts.py
#          /in/hermes-env (optional; the only secret-bearing input)
# Output:  /out/casper-rw.img
set -Eeuo pipefail

size_mib=${1:?missing size in MiB}
[[ $size_mib =~ ^[0-9]+$ ]] || { echo 'size must be an integer' >&2; exit 2; }
img=/out/casper-rw.img
stage=/stage
upper=$stage/upper
state_rel=home/mint/.local/share/rescue-omes
log() { printf '[image] %s\n' "$*"; }

rm -rf -- "$stage"
mkdir -p "$upper" "$stage/work"
chmod 0755 "$stage" "$upper" "$stage/work"

log 'extracting layer (ownership, modes and xattrs preserved)'
tar -xf /in/layer.tar -C "$upper" --numeric-owner --same-owner -p --xattrs --xattrs-include='*'
python3 /in/overlay_whiteouts.py prepare /in/plan.json "$upper"

if [[ -f /in/hermes-env ]]; then
  dest=$upper/$state_rel/hermes/env
  [[ -d $(dirname -- "$dest") ]] || { echo 'state directory missing in layer; refusing to provision' >&2; exit 1; }
  install -o 1000 -g 1000 -m 0600 /in/hermes-env "$dest"
  rm -f /in/hermes-env
  log 'API key provisioned into hermes/env (0600, uid 1000); value not printed'
else
  log 'no secret provisioning requested'
fi

used_mib=$(du -sm --apparent-size "$stage" | cut -f1)
log "staged content: ${used_mib} MiB; image size: ${size_mib} MiB"
if ((used_mib * 100 > size_mib * 85)); then
  echo "staged content (${used_mib} MiB) leaves too little free space in ${size_mib} MiB; raise --size-mib" >&2
  exit 1
fi

rm -f -- "$img"
truncate -s "${size_mib}M" "$img"
mkfs.ext4 -F -q -L casper-rw -m 0 -d "$stage" "$img"

# overlayfs (this container's filesystem) refuses to create 0:0 whiteout devices
# and trusted.* xattrs need CAP_SYS_ADMIN, so both are written straight into the
# finished image with debugfs, which edits the file and needs no privilege.
python3 /in/overlay_whiteouts.py debugfs /in/plan.json > /tmp/whiteouts.dbg
if [[ -s /tmp/whiteouts.dbg ]]; then
  debugfs -w -f /tmp/whiteouts.dbg "$img" >/tmp/whiteouts.log 2>&1 || true
  python3 /in/overlay_whiteouts.py verify /in/plan.json > /tmp/verify.dbg
  debugfs -f /tmp/verify.dbg "$img" >/tmp/verify.log 2>&1 || true
  want_wh=$(python3 -c 'import json;print(len(set(json.load(open("/in/plan.json"))["whiteouts"])))')
  want_op=$(python3 -c 'import json;print(len(set(json.load(open("/in/plan.json"))["opaque"])))')
  got_wh=$(grep -c 'Type: character special' /tmp/verify.log || true)
  got_dev=$(grep -c 'Device major/minor number: 00:00' /tmp/verify.log || true)
  got_op=$(grep -c '^trusted.overlay.opaque (1) = "y"' /tmp/verify.log || true)
  if [[ $got_wh != "$want_wh" || $got_dev != "$want_wh" || $got_op != "$want_op" ]]; then
    echo "whiteout/opaque read-back mismatch: whiteouts $got_wh/$got_dev of $want_wh, opaque $got_op of $want_op" >&2
    tail -20 /tmp/whiteouts.log >&2
    exit 1
  fi
  log "whiteouts (char 0:0) written and read back: $want_wh; opaque directories: $want_op"
else
  log 'no whiteouts or opaque directories in this layer'
fi

e2fsck -fn "$img"
dumpe2fs -h "$img" 2>/dev/null | grep -E '^(Filesystem volume name|Filesystem features|Block count|Free blocks|Inode count|Free inodes):'
chmod 0644 "$img"
log 'image written'
