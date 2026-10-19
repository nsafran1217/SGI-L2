# Sourced by the unit tests after they make $tmp: headers the faithful
# reconstruction (RECON_REF) includes but this tree has deleted are taken
# from it into $tmp/recon, whose directories go on CPATH (after every -I),
# so its sources still compile here.
recon_ref=${RECON_REF:-origin/main}
for h in $(git ls-tree -r --name-only "$recon_ref" sys_ctrl | grep '\.h$'); do
    [ -e "$h" ] && continue
    mkdir -p "$tmp/recon/$(dirname "$h")"
    git show "$recon_ref:$h" > "$tmp/recon/$h"
done
for d in $(git ls-tree -d -r --name-only "$recon_ref" sys_ctrl); do
    mkdir -p "$tmp/recon/$d"
    CPATH=${CPATH:+$CPATH:}$tmp/recon/$d
done
export CPATH
