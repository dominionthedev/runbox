#!/bin/sh
# verify_cross_account.sh
#
# Creates one throwaway hidden account (same shape identity::provision
# will use), runs verify as that account via `sudo -u`, then
# deletes the account.
#
# Run from the same directory as the compiled `verify` binary:
#   ./verify_cross_account.sh

set -e

ACCOUNT="_runbox_verify_test"

if [ ! -x ./verify ]; then
    echo "building verify.c:"
    cc verify.c -o verify
fi

find_free_uid() {
    used=$(dscl . -list /Users UniqueID | awk '{print $2}')
    for candidate in $(seq 750 799); do
        if ! echo "$used" | grep -qx "$candidate"; then
            echo "$candidate"
            return 0
        fi
    done
    echo "no free uid found in 750-799" >&2
    exit 1
}

if dscl . -read /Users/$ACCOUNT >/dev/null 2>&1; then
    echo "leftover $ACCOUNT from a previous run — removing it first"
    sudo dscl . -delete /Users/$ACCOUNT
fi

UID_NUM=$(find_free_uid)
echo "creating $ACCOUNT (uid $UID_NUM) — same shape as a real runbox-managed account"

sudo dscl . -create /Users/$ACCOUNT
sudo dscl . -create /Users/$ACCOUNT UserShell /usr/bin/false
sudo dscl . -create /Users/$ACCOUNT UniqueID "$UID_NUM"
sudo dscl . -create /Users/$ACCOUNT PrimaryGroupID 20
sudo dscl . -create /Users/$ACCOUNT NFSHomeDirectory /var/empty
sudo dscl . -create /Users/$ACCOUNT IsHidden 1
sudo dscl . -create /Users/$ACCOUNT AuthenticationAuthority ";DisabledUser;"

echo ""
echo "=== running verify as $(whoami) ==="
./verify || true

echo ""
echo "=== running verify as $ACCOUNT (via sudo -u) ==="
sudo -u "$ACCOUNT" ./verify || true

echo ""
echo "cleaning up: deleting $ACCOUNT"
sudo dscl . -delete /Users/$ACCOUNT
echo "done"
