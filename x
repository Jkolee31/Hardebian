#!/bin/sh
set -eu

# =========================
# CONFIG — TUNE IF NEEDED
# =========================
DISK="/dev/nvme0n1"                     # e.g. /dev/sda or /dev/nvme0n1
ESP_SIZE_MIB=512
VG_NAME="vg0"
LV_ROOT_SIZE="30G"
LV_VAR_SIZE="15G"
LV_LOG_SIZE="4G"
SWAP_SIZE="auto"                    # "auto" or e.g. "8G"
FS_LABEL_ROOT="alpine_root"
FS_LABEL_VAR="alpine_var"
FS_LABEL_LOG="alpine_log"
FS_LABEL_HOME="alpine_home"
ESP_LABEL="EFI"

# LUKS
LUKS_NAME="cryptroot"
LUKS_CIPHER="aes-xts-plain64"
LUKS_KEY_SIZE="512"
LUKS_PBKDF="argon2id"
LUKS_ITER_MS="5000"

# Secure Boot (custom keys)
SB_CN_PREFIX="Alpine Local"
SB_DIR="/mnt/boot/efi-secure"       # staging on ESP for tools/keys/docs
SB_COUNTRY="US"
SB_STATE="NA"
SB_LOCALITY="NA"
SB_ORG="Local"
SB_EMAIL="root@localhost"

# =========================
# sanity checks
# =========================
[ -d /sys/firmware/efi/efivars ] || { echo "ERROR: Not booted in UEFI mode."; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
# base tooling
for b in parted sgdisk cryptsetup pvcreate vgcreate lvcreate mkfs.vfat mkfs.ext4 mkswap lsblk awk sed findmnt; do need "$b"; done
# alpine install + pkgs
for b in apk setup-disk; do need "$b"; end
done 2>/dev/null || true # quiet shellcheck
# secure boot tools (will install inside chroot too)
# we only require openssl here; KeyTool.efi comes from efitools package installed inside the target
need openssl

[ -b "$DISK" ] || { echo "ERROR: $DISK not a block device"; exit 1; }

case "$DISK" in
  /dev/nvme*) P1="${DISK}p1"; P2="${DISK}p2" ;;
  *)          P1="${DISK}1";  P2="${DISK}2"  ;;
esac

echo ">>> THIS WILL WIPE $DISK. Type YES to continue:"
read -r CONFIRM
[ "$CONFIRM" = "YES" ] || { echo "Aborted."; exit 1; }

# =========================
# Partition
# =========================
wipefs -a "$DISK" || true
sgdisk --zap-all "$DISK"
parted -s "$DISK" mklabel gpt
parted -s "$DISK" mkpart ESP fat32 1MiB "$((ESP_SIZE_MIB+1))MiB"
parted -s "$DISK" set 1 esp on
parted -s "$DISK" mkpart cryptroot "$((ESP_SIZE_MIB+1))MiB" 100%
parted "$DISK" print

# =========================
# LUKS
# =========================
cryptsetup luksFormat \
  --type luks2 \
  --cipher "$LUKS_CIPHER" \
  --key-size "$LUKS_KEY_SIZE" \
  --pbkdf "$LUKS_PBKDF" \
  --iter-time "$LUKS_ITER_MS" \
  --use-random \
  "$P2"

cryptsetup open "$P2" "$LUKS_NAME"
MAPPER="/dev/mapper/$LUKS_NAME"

# =========================
# LVM
# =========================
pvcreate "$MAPPER"
vgcreate "$VG_NAME" "$MAPPER"

calc_swap() {
  mem_kb=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
  mem_g=$(( (mem_kb + 1048575) / 1048576 ))
  [ $mem_g -lt 2 ] && mem_g=2
  [ $mem_g -gt 16 ] && mem_g=16
  echo "${mem_g}G"
}
[ "$SWAP_SIZE" = "auto" ] && SWAP_SIZE="$(calc_swap)"

lvcreate -L "$LV_ROOT_SIZE" -n root "$VG_NAME"
lvcreate -L "$LV_VAR_SIZE"  -n var  "$VG_NAME"
lvcreate -L "$LV_LOG_SIZE"  -n log  "$VG_NAME"
lvcreate -L "$SWAP_SIZE"    -n swap "$VG_NAME"
lvcreate -l 100%FREE -n home "$VG_NAME"

# =========================
# Filesystems + mounts
# =========================
mkfs.vfat -F32 -n "$ESP_LABEL" "$P1"
mkfs.ext4 -L "$FS_LABEL_ROOT" "/dev/${VG_NAME}/root"
mkfs.ext4 -L "$FS_LABEL_VAR"  "/dev/${VG_NAME}/var"
mkfs.ext4 -L "$FS_LABEL_LOG"  "/dev/${VG_NAME}/log"
mkfs.ext4 -L "$FS_LABEL_HOME" "/dev/${VG_NAME}/home"
mkswap "/dev/${VG_NAME}/swap"

mount "/dev/${VG_NAME}/root" /mnt
mkdir -p /mnt/{boot,home,var/log}
mount "$P1" /mnt/boot
mount "/dev/${VG_NAME}/var"  /mnt/var
mount "/dev/${VG_NAME}/log"  /mnt/var/log
mount "/dev/${VG_NAME}/home" /mnt/home
swapon "/dev/${VG_NAME}/swap"

# fstab/crypttab scaffolds
mkdir -p /mnt/etc
ROOT_UUID=$(blkid -s UUID -o value "/dev/${VG_NAME}/root")
VAR_UUID=$(blkid -s UUID -o value "/dev/${VG_NAME}/var")
LOG_UUID=$(blkid -s UUID -o value "/dev/${VG_NAME}/log")
HOME_UUID=$(blkid -s UUID -o value "/dev/${VG_NAME}/home")
ESP_UUID=$(blkid -s UUID -o value "$P1")
SWAP_UUID=$(blkid -s UUID -o value "/dev/${VG_NAME}/swap")

cat > /mnt/etc/fstab <<EOF
UUID=$ROOT_UUID  /          ext4  defaults,relatime                         0 1
UUID=$ESP_UUID   /boot      vfat  defaults,umask=0077                       0 2
UUID=$VAR_UUID   /var       ext4  nodev,nosuid,relatime                      0 2
UUID=$LOG_UUID   /var/log   ext4  noexec,nodev,nosuid,relatime               0 2
UUID=$HOME_UUID  /home      ext4  nodev,nosuid,relatime                      0 2
UUID=$SWAP_UUID  none       swap  sw                                         0 0
tmpfs            /tmp       tmpfs defaults,noexec,nodev,nosuid,mode=1777,size=2g 0 0
EOF

cat > /mnt/etc/crypttab <<EOF
$LUKS_NAME UUID=$(blkid -s UUID -o value "$P2") none luks
EOF

# =========================
# Install base system
# =========================
setup-disk -m sys /mnt

# =========================
# In-chroot setup: pkgs, initramfs, grub
# =========================
KCMD="cryptdevice=UUID=$(blkid -s UUID -o value "$P2"):$LUKS_NAME root=/dev/${VG_NAME}/root rootfstype=ext4"

cat > /mnt/root/_in_chroot.sh <<CHROOT_EOF
#!/bin/sh
set -eu
apk update
apk add --no-interactive cryptsetup lvm2 grub-efi efibootmgr \
  efitools sbsigntool openssl                  # secure-boot tools

# mkinitfs config
echo 'features="base crypt lvm"' > /etc/mkinitfs/mkinitfs.conf
mkinitfs

# grub config
echo 'GRUB_CMDLINE_LINUX="$KCMD"' >/etc/default/grub
grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=alpine --recheck
grub-mkconfig -o /boot/grub/grub.cfg
CHROOT_EOF
chmod +x /mnt/root/_in_chroot.sh
chroot /mnt /bin/ash /root/_in_chroot.sh
rm -f /mnt/root/_in_chroot.sh

# =========================
# Secure Boot (Custom Mode) PREP
# - generate PK/KEK/db
# - sign grubx64.efi + vmlinuz
# - copy KeyTool.efi to ESP and create a boot entry
# NOTE: Key enrollment happens at next boot via KeyTool.
# =========================
mkdir -p "$SB_DIR"
KDIR="$SB_DIR/keys"
EDIR="$SB_DIR/efi"
mkdir -p "$KDIR" "$EDIR"

# generate keys (PEM + DER)
gen_cert() {
  name="$1"
  subj="/C=$SB_COUNTRY/ST=$SB_STATE/L=$SB_LOCALITY/O=$SB_ORG/CN=$SB_CN_PREFIX $name/emailAddress=$SB_EMAIL"
  openssl req -new -x509 -newkey rsa:4096 -sha256 -nodes -days 3650 -subj "$subj" \
    -keyout "$KDIR/$name.key" -out "$KDIR/$name.crt"
  openssl x509 -outform DER -in "$KDIR/$name.crt" -out "$KDIR/$name.cer"
}
gen_cert PK
gen_cert KEK
gen_cert db

# Copy KeyTool.efi from target (efitools) into ESP
if [ -f /mnt/usr/share/efitools/efi/KeyTool.efi ]; then
  cp /mnt/usr/share/efitools/efi/KeyTool.efi "$EDIR/KeyTool.efi"
else
  echo "WARN: KeyTool.efi not found. Ensure 'efitools' installed in target."
fi

# Prepare signed GRUB and kernel
BOOTDIR="/mnt/boot"
EFI_ALPINE_DIR="/mnt/boot/EFI/alpine"
mkdir -p "$EFI_ALPINE_DIR"
GRUB_EFI="$EFI_ALPINE_DIR/grubx64.efi"
KERNEL_IMG=$(ls -1 "$BOOTDIR"/vmlinuz-* 2>/dev/null | head -n1 || true)

# Extract the installed grub EFI binary
# grub-install already placed grubx64.efi to /boot/EFI/alpine/grubx64.efi
[ -f "$GRUB_EFI" ] || { echo "ERROR: grubx64.efi not found at $GRUB_EFI"; exit 1; }
[ -n "$KERNEL_IMG" ] || { echo "ERROR: Kernel image not found in /boot"; exit 1; }

# Sign with db key
sbsign --key "$KDIR/db.key" --cert "$KDIR/db.crt" --output "$EFI_ALPINE_DIR/grubx64.signed.efi" "$GRUB_EFI"
sbsign --key "$KDIR/db.key" --cert "$KDIR/db.crt" --output "$BOOTDIR/$(basename "$KERNEL_IMG").signed" "$KERNEL_IMG"

# Document next steps on ESP
cat > "$SB_DIR/README-SECURE-BOOT.txt" <<DOC
Custom Secure Boot (Alpine):
1) On next boot, choose the "KeyTool" boot entry.
2) Enroll keys in this order:
   - Enroll PK (Platform Key): $KDIR/PK.cer
   - Enroll KEK: $KDIR/KEK.cer
   - Enroll db (Signature Database): $KDIR/db.cer
3) After enrollment, enable Secure Boot in firmware if needed.
4) Boot "Alpine (signed)" entry. GRUB: /EFI/alpine/grubx64.signed.efi
   Kernel is signed: $(basename "$KERNEL_IMG").signed
5) Update kernel? Re-sign with sbsign using db.key/db.crt.

If KeyTool is missing, ensure 'efitools' is installed in target and re-run SB section.
DOC

# Create dedicated boot entry for KeyTool and for signed GRUB
# (efibootmgr works from live environment as long as ESP is mounted)
efibootmgr -c -d "$DISK" -p 1 -L "KeyTool (Enroll SB Keys)" -l "\\EFI\\efi-secure\\KeyTool.efi" || true
efibootmgr -c -d "$DISK" -p 1 -L "Alpine (signed)" -l "\\EFI\\alpine\\grubx64.signed.efi" || true

echo
echo "==================================================="
echo " All done."
echo
echo " Reboot flow for Secure Boot:"
echo "  1) Reboot, select 'KeyTool (Enroll SB Keys)'."
echo "  2) Enroll PK -> KEK -> db from: \\EFI\\efi-secure\\keys\\*.cer"
echo "  3) Turn on Secure Boot (if not already)."
echo "  4) Boot 'Alpine (signed)'."
echo
echo " Non-Secure-Boot fallback always available via normal 'alpine' GRUB entry."
echo
echo " Before reboot you can set root password in chroot:"
echo "   chroot /mnt /bin/ash -lc 'passwd'"
echo
echo " When ready:"
echo "   umount -R /mnt; swapoff -a; cryptsetup close $LUKS_NAME; reboot"
echo "==================================================="