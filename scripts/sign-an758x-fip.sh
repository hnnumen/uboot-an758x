#!/bin/sh

set -eu

[ "$#" -eq 3 ] || { echo "usage: $0 <tf-a-tree> <preloader-fip> <bl31-uboot-fip>" >&2; exit 2; }

# Ephemeral key fallback.
#
# Skipping signing is NOT safe: an unsigned FIP only carries the BL31 and
# BL33 ToC entries, so BL2 cannot find the certificate chain it expects and
# refuses to hand over to U-Boot. The board then comes up completely dark
# (no LEDs at all), which looks like a dead unit. Signing with a throwaway
# RSA-4096 key keeps the ToC structurally complete, which is what the boot
# chain actually requires.
ephemeral=0

if [ -n "${AIROHA_SIGN_KEY_PATH:-}" ] && [ -f "$AIROHA_SIGN_KEY_PATH" ]; then
	key_path="$(readlink -f -- "$AIROHA_SIGN_KEY_PATH")"
elif [ -n "${AIROHA_SIGN_KEY:-}" ]; then
	key_path=
elif [ -n "${AIROHA_SIGN_KEY_PATH:-}" ]; then
	echo "Signing key path does not name a file." >&2
	exit 1
else
	echo "AIROHA_SIGN_KEY unset - signing with a generated RSA-4096 key." >&2
	key_path=
	ephemeral=1
fi

tfa="$(readlink -f -- "$1")"
preloader="$(readlink -f -- "$2")"
stage2="$(readlink -f -- "$3")"
umask 077
work="$(mktemp -d "$tfa/signing.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM
if [ -z "$key_path" ]; then
	key_path="$work/root.pem"
	if [ "$ephemeral" -eq 1 ]; then
		openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
			-out "$key_path"
	else
		printf '%s\n' "$AIROHA_SIGN_KEY" > "$key_path"
	fi
fi
unset AIROHA_SIGN_KEY

openssl pkey -in "$key_path" -passin pass: -pubout -out "$work/root.pub"
openssl pkey -pubin -in "$work/root.pub" -text -noout > "$work/root.txt"
grep -q 'Public-Key: (4096 bit)' "$work/root.txt" || {
	echo "Signing requires RSA-4096." >&2
	exit 1
}

make -C "$tfa/tools/cert_create" HOSTCC=cc
fiptool="$tfa/tools/fiptool/fiptool"
cert_create="$tfa/tools/cert_create/cert_create"
"$fiptool" unpack --tb-fw "$work/bl2.bin" "$preloader"
"$fiptool" unpack --soc-fw "$work/bl31.bin" --nt-fw "$work/u-boot.bin" "$stage2"
(
	cd "$work"
	"$cert_create" -n --key-alg rsa --key-size 4096 --hash-alg sha512 \
		--tfw-nvctr 0 --ntfw-nvctr 0 --rot-key "$key_path" \
		--tb-fw bl2.bin --tb-fw-cert tb-fw.crt
	"$cert_create" -n --key-alg rsa --key-size 4096 --hash-alg sha512 \
		--tfw-nvctr 0 --ntfw-nvctr 0 --rot-key "$key_path" \
		--soc-fw bl31.bin --nt-fw u-boot.bin \
		--trusted-key-cert trusted-key.crt \
		--soc-fw-key-cert soc-fw-key.crt --soc-fw-cert soc-fw.crt \
		--nt-fw-key-cert nt-fw-key.crt --nt-fw-cert nt-fw.crt
	"$fiptool" create --align 1024 --tb-fw bl2.bin --tb-fw-cert tb-fw.crt preloader.fip
	"$fiptool" create --align 1024 --soc-fw bl31.bin --nt-fw u-boot.bin \
		--trusted-key-cert trusted-key.crt \
		--soc-fw-key-cert soc-fw-key.crt --soc-fw-cert soc-fw.crt \
		--nt-fw-key-cert nt-fw-key.crt --nt-fw-cert nt-fw.crt stage2.fip
)

# These windows include certificates and padding: BL2 follows the 0x800-byte
# boot prefix; the next-stage FIP occupies the platform's 0x7f800-byte window.
[ "$(wc -c < "$work/preloader.fip")" -le "$((0x1f800))" ] &&
[ "$(wc -c < "$work/stage2.fip")" -le "$((0x7f800))" ] || {
	echo "Signed FIP exceeds the boot image window." >&2
	exit 1
}

# Count the ToC entries and fail the build if the certificate chain is
# missing. The ToC starts at 0x10 and holds 40-byte entries terminated by an
# all-zero UUID; stage2 needs BL31 + BL33 plus five certificates, preloader
# needs BL2 plus its certificate.
# heredocs inside command substitution are not portable across all /bin/sh
# implementations, so write the checker to a file and run that instead.
cat > "$work/toc_count.py" <<'PY'
import sys

data = open(sys.argv[1], 'rb').read()
count = 0
off = 0x10
while off + 40 <= len(data):
    if data[off:off + 16] == b'\x00' * 16:
        break
    count += 1
    off += 40
print(count)
PY

verify_toc() {
	label="$1"
	fip="$2"
	want="$3"

	if ! command -v python3 >/dev/null 2>&1; then
		echo "python3 unavailable - skipping ToC check for $label." >&2
		return 0
	fi

	got=$(python3 "$work/toc_count.py" "$fip")
	[ "$got" -eq "$want" ] || {
		echo "Incomplete FIP: $label has $got ToC entries, expected $want." >&2
		echo "An incomplete FIP boots dark (no LEDs) - refusing to ship it." >&2
		return 1
	}
	echo "$label: $got ToC entries, complete." >&2
}

verify_toc "preloader" "$work/preloader.fip" 2 &&
verify_toc "bl31-u-boot" "$work/stage2.fip" 7 || exit 1

cp "$work/preloader.fip" "$preloader"
cp "$work/stage2.fip" "$stage2"
echo "Preloader and BL31/U-Boot FIPs signed."
