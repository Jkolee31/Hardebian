#!/bin/sh
# alpine_fde_prep_v2.sh
set -eu

# ---- CONFIG ----
DISK="/dev/sda"           # /dev/sda or /dev/nvme0n1
ESP_SIZE_MIB=512
VG_NAME="vg0"
LV_ROOT_SIZE="30G"
LV_VAR_SIZE="15G"
LV_LOG_SIZE="4G"
SWAP_SIZE="auto"          # or "8G"
FS_LABEL_ROOT="alpine_root"
FS_LABEL_VAR="alpine_var"
FS_LABEL_LOG="alpine_log"
FS_LABEL_HOME="alpine_home"
ESP_LABEL="EFI"

# LUKS params
LUKS_NAME="cryptroot"
LUKS_CIPHER="aes-xts-plain64"
LUKS_KEY_SIZE="512"
LUKS_PBKDF="argon2id"
LUKS_ITER_MS="5000"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
for b in parted sgdisk cryptsetup pvcreate vgcreate lvcreate mkfs.vfat mkfs.ext4 mkswap lsblk blkid modprobe; do need "$b"; done
[ -b "$DISK" ] || { echo "ERROR: $DISK is not a block device"; exit 1; }

case "$DISK" in
  /dev/nvme*) P1="${DISK}p1"; P2="${DISK}p2" ;;
  *)          P1="${DISK}1";  P2="${DISK}2"  ;;
esac

echo ">>> THIS WILL WIPE $DISK. Type YES to proceed:"
read -r CONFIRM
[ "$CONFIRM" = "YES" ] || { echo "Aborted."; exit 1; }

echo "[*] Wiping and partitioning…"
wipefs -a "$DISK" || true
sgdisk --zap-all "$DISK"
parted -s "$DISK" mklabel gpt
parted -s "$DISK" mkpart ESP fat32 1MiB "$((ESP_SIZE_MIB+1))MiB"
parted -s "$DISK" set 1 esp on
parted -s "$DISK" mkpart cryptroot "$((ESP_SIZE_MIB+1))MiB" 100%
parted "$DISK" print

echo "[*] Creating LUKS2 on $P2…"
cryptsetup luksFormat --type luks2 --cipher "$LUKS_CIPHER" \
  --key-size "$LUKS_KEY_SIZE" --pbkdf "$LUKS_PBKDF" \
  --iter-time "$LUKS_ITER_MS" --use-random "$P2"

echo "[*] Opening LUKS as $LUKS_NAME…"
cryptsetup open "$P2" "$LUKS_NAME"
MAPPER="/dev/mapper/$LUKS_NAME"

echo "[*] LVM setup…"
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

echo "[*] Making filesystems…"
mkfs.vfat -F32 -n "$ESP_LABEL" "$P1"

# ext4 with broad compatibility (avoids rare live-ISO feature mismatches)
mkfs.ext4 -F -O ^metadata_csum_seed "/dev/${VG_NAME}/root" -L "$FS_LABEL_ROOT"
mkfs.ext4 -F -O ^metadata_csum_seed "/dev/${VG_NAME}/var"  -L "$FS_LABEL_VAR"
mkfs.ext4 -F -O ^metadata_csum_seed "/dev/${VG_NAME}/log"  -L "$FS_LABEL_LOG"
mkfs.ext4 -F -O ^metadata_csum_seed "/dev/${VG_NAME}/home" -L "$FS_LABEL_HOME"

mkswap "/dev/${VG_NAME}/swap"

echo "[*] Mounting…"
modprobe ext4 2>/dev/null || true
mkdir -p /mnt
mount -t ext4 "/dev/${VG_NAME}/root" /mnt

mkdir -p /mnt/{boot,home,var/log}
mount "$P1" /mnt/boot
mount -t ext4 "/dev/${VG_NAME}/var"  /mnt/var
mount -t ext4 "/dev/${VG_NAME}/log"  /mnt/var/log
mount -t ext4 "/dev/${VG_NAME}/home" /mnt/home
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

echo
echo "=== Mounted layout ==="
findmnt -R /mnt | sed 's/^/  /'
echo
echo "Next: apk add cryptsetup lvm2; setup-disk -m sys /mnt; chroot and finish bootloader."