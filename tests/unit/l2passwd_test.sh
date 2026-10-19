#!/bin/sh
# l2passwd on a fake root (SGI_L3_ROOT): the rebuilt one only, since the
# original rewrites the real /etc/passwd. With no L2 password, root's
# password is cleared and rhosts.allow becomes /etc/.rhosts; when the
# password file can't be backed up, it is left alone (the original
# emptied it).
set -eu
cd "$(dirname "$0")/../.."
bin=${NEW_BIN:-$PWD/build/bin}
tmp=$(mktemp -d)
trap 'chmod -R u+w "$tmp"; rm -rf "$tmp"' EXIT
mkdir -p "$tmp/etc"
printf 'root:xyz:0:0:root:/root:/bin/sh\nuser:abc:1000:1000:User:/home/user:/bin/sh\n' > "$tmp/etc/passwd"
echo "+ +" > "$tmp/rhosts.allow"
SGI_L3_ROOT=$tmp SGI_L2_NVRAM=$tmp/nvram "$bin/l2passwd" >/dev/null 2>&1 || true
grep -q '^root::0:0:root:/root:/bin/sh$' "$tmp/etc/passwd" || { echo "FAIL  l2passwd: root's password not cleared"; cat "$tmp/etc/passwd"; exit 1; }
grep -q '^user:abc:' "$tmp/etc/passwd" || { echo "FAIL  l2passwd: other entries lost"; exit 1; }
cmp -s "$tmp/rhosts.allow" "$tmp/etc/.rhosts" || { echo "FAIL  l2passwd: .rhosts not set"; exit 1; }
# no room for the backup: passwd must survive
printf 'root:xyz:0:0:root:/root:/bin/sh\n' > "$tmp/etc/passwd"
chmod a-w "$tmp/etc"
SGI_L3_ROOT=$tmp SGI_L2_NVRAM=$tmp/nvram "$bin/l2passwd" >/dev/null 2>&1 || true
chmod u+w "$tmp/etc"
grep -q '^root:xyz:' "$tmp/etc/passwd" || { echo "FAIL  l2passwd: passwd damaged when it couldn't be backed up"; exit 1; }
echo "PASS  l2passwd: root password follows the L2's; passwd kept when it can't be backed up"
