#!/bin/sh
set -eu

# =========================
# CONFIG (adjust as needed)
# =========================
DISK="/dev/nvme0n1"                # e.g. /dev/sda or /dev/nvme0n1
ESP_SIZE_MIB=512               # EFI System Partition size
VG_NAME="vg0"                  # LVM VG name
LV_ROOT_SIZE="30G"             # root LV size
LV_VAR_SIZE="15G"              # /var LV size
LV_LOG_SIZE="4G"               # /var/log LV size
SWAP_SIZE="auto"               # "auto" or like "4G"
FS_LABEL_ROOT="alpine_root"
FS_LABEL_VAR="alpine_var"
FS_LABEL_LOG="alpine_log"
FS_LABEL_HOME="alpine_home"
ESP_LABEL="EFI"

# LUKS parameters (hardened but practical)
LUKS_NAME="cryptroot"
LUKS_CIPHER="aes-xts-plain64"
LUKS_KEY_SIZE="512"            # 512-bit XTS (256-bit key * 2)
LUKS_PBKDF="argon2id"
LUKS_ITER_MS="5000"            # ~5s derivation on installer HW
LUKS_SLOT="0"

# =========================
# sanity checks
# =========================
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
for bin in parted sgdisk cryptsetup pvcreate vgcreate lvcreate mkfs.vfat mkfs.ext4 mkswap lsblk; do need "$bin"; done
[ -b "$DISK" ] || { echo "ERROR: $DISK is not a block device"; exit 1; }

case "$DISK" in
  /dev/nvme*) P1="${DISK}p1"; P2="${DISK}p2" ;;
  *)          P1="${DISK}1";  P2="${DISK}2"  ;;
esac

echo ">>> THIS WILL WIPE $DISK. Type YES to continue:"
read -r CONFIRM
[ "$CONFIRM" = "YES" ] || { echo "Aborted."; exit 1; }

# =========================
# partition
# =========================
echo "[*] Wiping partition table on $DISK..."
wipefs -a "$DISK" || true
sgdisk --zap-all "$DISK"

echo "[*] Creating GPT..."
parted -s "$DISK" mklabel gpt

echo "[*] Creating ESP ${ESP_SIZE_MIB}MiB and LUKS partition..."
parted -s "$DISK" \
  mkpart ESP fat32 1MiB "$((ESP_SIZE_MIB+1))MiB" \
  set 1 esp on \
  mkpart cryptroot "$((ESP_SIZE_MIB+1))MiB" 100%

parted "$DISK" print

# =========================
# LUKS
# =========================
echo "[*] Formatting LUKS2 on $P2 (you will be prompted for passphrase)..."
cryptsetup luksFormat \
  --type luks2 \
  --cipher "$LUKS_CIPHER" \
  --key-size "$LUKS_KEY_SIZE" \
  --pbkdf "$LUKS_PBKDF" \
  --iter-time "$LUKS_ITER_MS" \
  --use-random \
  "$P2"

echo "[*] Opening LUKS container as $LUKS_NAME..."
cryptsetup open "$P2" "$LUKS_NAME"

MAPPER="/dev/mapper/$LUKS_NAME"

# =========================
# LVM
# =========================
echo "[*] Initializing LVM on $MAPPER..."
pvcreate "$MAPPER"
vgcreate "$VG_NAME" "$MAPPER"

# Auto swap sizing based on RAM (min 2G, max 16G, ~1.0x RAM up to 16G)
calc_swap() {
  mem_kb=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
  mem_g=$(( (mem_kb + 1048575) / 1048576 ))    # round up
  [ $mem_g -lt 2 ] && mem_g=2
  [ $mem_g -gt 16 ] && mem_g=16
  echo "${mem_g}G"
}

if [ "$SWAP_SIZE" = "auto" ]; then
  SWAP_SIZE="$(calc_swap)"
fi
echo "[*] Using swap size: $SWAP_SIZE"

echo "[*] Creating LVs..."
lvcreate -L "$LV_ROOT_SIZE" -n root "$VG_NAME"
lvcreate -L "$LV_VAR_SIZE"  -n var  "$VG_NAME"
lvcreate -L "$LV_LOG_SIZE"  -n log  "$VG_NAME"
lvcreate -L "$SWAP_SIZE"    -n swap "$VG_NAME"
# Home gets the rest
lvcreate -l 100%FREE -n home "$VG_NAME"

# =========================
# filesystems
# =========================
echo "[*] Making filesystems..."
mkfs.vfat -F32 -n "$ESP_LABEL" "$P1"

mkfs.ext4 -L "$FS_LABEL_ROOT" "/dev/${VG_NAME}/root"
mkfs.ext4 -L "$FS_LABEL_VAR"  "/dev/${VG_NAME}/var"
mkfs.ext4 -L "$FS_LABEL_LOG"  "/dev/${VG_NAME}/log"
mkfs.ext4 -L "$FS_LABEL_HOME" "/dev/${VG_NAME}/home"

mkswap "/dev/${VG_NAME}/swap"

# =========================
# mount
# =========================
echo "[*] Mounting target at /mnt..."
mount "/dev/${VG_NAME}/root" /mnt
mkdir -p /mnt/{boot,home,var/log}
mount "$P1" /mnt/boot
mount "/dev/${VG_NAME}/var"  /mnt/var
mount "/dev/${VG_NAME}/log"  /mnt/var/log
mount "/dev/${VG_NAME}/home" /mnt/home
swapon "/dev/${VG_NAME}/swap"

# =========================
# fstab + crypttab templates (helpful scaffolding)
# =========================
mkdir -p /mnt/etc
ROOT_UUID=$(blkid -s UUID -o value "/dev/${VG_NAME}/root")
VAR_UUID=$(blkid -s UUID -o value "/dev/${VG_NAME}/var")
LOG_UUID=$(blkid -s UUID -o value "/dev/${VG_NAME}/log")
HOME_UUID=$(blkid -s UUID -o value "/dev/${VG_NAME}/home")
ESP_UUID=$(blkid -s UUID -o value "$P1")
SWAP_UUID=$(blkid -s UUID -o value "/dev/${VG_NAME}/swap")

cat > /mnt/etc/fstab <<EOF
# /etc/fstab - generated scaffold (review after setup-disk)
UUID=$ROOT_UUID  /          ext4  defaults,relatime                         0 1
UUID=$ESP_UUID   /boot      vfat  defaults,umask=0077                       0 2
UUID=$VAR_UUID   /var       ext4  nodev,nosuid,relatime                      0 2
UUID=$LOG_UUID   /var/log   ext4  noexec,nodev,nosuid,relatime               0 2
UUID=$HOME_UUID  /home      ext4  nodev,nosuid,relatime                      0 2
UUID=$SWAP_UUID  none       swap  sw                                         0 0
tmpfs            /tmp       tmpfs defaults,noexec,nodev,nosuid,mode=1777,size=2g 0 0
EOF

cat > /mnt/etc/crypttab <<EOF
# /etc/crypttab - unlock root LUKS at boot
$LUKS_NAME UUID=$(blkid -s UUID -o value "$P2") none luks,discard
EOF

echo
echo "==================================================="
echo " Done."
echo " Mounted target:"
findmnt -R /mnt | sed 's/^/  /'
echo
echo " Next steps (inside the live environment):"
echo "   1) apk add cryptsetup lvm2"
echo "   2) setup-disk -m sys /mnt"
echo "   3) chroot /mnt /bin/ash"
echo "   4) apk add cryptsetup lvm2"
echo "   5) echo 'features=\"base crypt lvm2\"' > /etc/mkinitfs/mkinitfs.conf && mkinitfs"
echo "   6) apk add grub-efi && grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=alpine"
echo "   7) echo 'GRUB_CMDLINE_LINUX=\"cryptdevice=$P2:$LUKS_NAME root=/dev/${VG_NAME}/root\"' > /etc/default/grub"
echo "      grub-mkconfig -o /boot/grub/grub.cfg"
echo "   8) passwd; exit; umount -R /mnt; swapoff -a; cryptsetup close $LUKS_NAME; reboot"
echo "==================================================="