#!/usr/bin/env bash
set -euo pipefail

###======================= USER VARS (EDIT ME) ================================
DISK="/dev/nvme0n1"            # e.g. /dev/sda or /dev/nvme0n1 (NO trailing slash)
HOSTNAME="alpine"
TIMEZONE="America/New_York"                 # e.g. America/New_York
KEYMAP="us"
ROOT_PASSWORD="********"
NEW_USER="dev"              # "" to skip
NEW_USER_PASSWORD="********"
NEW_USER_SUDO="yes"            # yes|no

# Networking (simple DHCP; tune if needed)
NET_IFACE="eth0"
USE_DHCP="no"                 # yes|no
STATIC_IP="192.168.88.227"
STATIC_GW="192.168.88.1"
STATIC_DNS="192.168.88.1"

# APK mirrors
APK_REPO="https://dl-cdn.alpinelinux.org/alpine/latest-stable/main"
APK_REPO_COMMUNITY="https://dl-cdn.alpinelinux.org/alpine/latest-stable/community"

# Partition sizes
EFI_SIZE="512MiB"
BOOT_SIZE="1GiB"

# LVM sizes (leave some free VG for growth if you can)
LV_ROOT_SIZE="50G"
LV_HOME_SIZE="20G"
LV_VAR_SIZE="20G"
LV_VAR_LOG_SIZE="20G"
LV_VAR_LOG_AUDIT_SIZE="20G"
LV_TMP_SIZE="10G"
LV_VAR_TMP_SIZE="10G"
LV_SWAP_SIZE=""                # e.g. "4G" or leave empty for none

# Filesystems
FS_BOOT="ext4"
FS_DATA="ext4"

# SSH
ENABLE_SSH="no"               # yes|no
PERMIT_ROOT_SSH="no"           # yes|no
AUTHORIZED_KEY=""              # optional: ssh-ed25519 AAAA...

###===================== DERIVED / CONSTANTS =================================
DISK="${DISK%/}"               # strip trailing slash, just in case

# NVMe/mmc need pN partition names
case "$DISK" in
  *nvme*|*mmcblk*) PART_PREFIX="${DISK}p" ;;
  *)               PART_PREFIX="${DISK}"  ;;
esac
P1="${PART_PREFIX}1"    # EFI (or BIOS-boot slice)
P2="${PART_PREFIX}2"    # /boot
P3="${PART_PREFIX}3"    # LUKS PV

MNT="/mnt"
VG="vg0"
MAP="luks_main"

# Mount options
TMP_OPTS="defaults,nodev,nosuid,noexec"
VAR_TMP_OPTS="defaults,nodev,nosuid,noexec"
VAR_OPTS="defaults"
VAR_LOG_OPTS="defaults,nodev,nosuid,noexec"
VAR_LOG_AUDIT_OPTS="defaults,nodev,nosuid,noexec"
HOME_OPTS="defaults,nodev,nosuid"
ROOT_OPTS="defaults"
BOOT_OPTS="defaults"
EFI_OPTS="defaults"

###===================== HELPERS =============================================
need() { command -v "$1" >/dev/null 2>&1 || apk add --no-progress "$1"; }
wait_block() {
  local dev="$1" tries="${2:-50}"
  for i in $(seq 1 "$tries"); do
    [ -b "$dev" ] && return 0
    sleep 0.2
  done
  echo "ERROR: Block device $dev not found." >&2
  lsblk || true
  exit 1
}
settle() { partprobe "$DISK" || true; udevadm settle 2>/dev/null || true; sleep 1; }

###===================== SAFETY & PRECHECKS ==================================
echo ">>> This will WIPE ${DISK}. Type YES to proceed."
read -r CONFIRM; [ "${CONFIRM:-}" = "YES" ] || { echo "Aborting."; exit 1; }

need sgdisk; need cryptsetup; need lvm2; need e2fsprogs; need dosfstools; need curl || true
need alpine-conf || true

# Boot mode
if [ -d /sys/firmware/efi/efivars ]; then BOOT_MODE="uefi"; else BOOT_MODE="bios"; fi
echo ">>> Detected boot mode: ${BOOT_MODE}"

###===================== NETWORK (for packages) ===============================
if [ "${USE_DHCP}" = "yes" ]; then
  ip link set "$NET_IFACE" up 2>/dev/null || true
  udhcpc -i "$NET_IFACE" -q -s /usr/share/udhcpc/default.script 2>/dev/null || true
fi

###===================== PARTITION (GPT both modes) ==========================
echo ">>> Zapping and partitioning ${DISK}"
sgdisk --zap-all "${DISK}"
sgdisk -o "${DISK}"

if [ "${BOOT_MODE}" = "uefi" ]; then
  sgdisk -n 1:0:+"${EFI_SIZE}"  -t 1:ef00 -c 1:"EFI System" "${DISK}"
else
  sgdisk -n 1:0:+1MiB -t 1:ef02 -c 1:"BIOS boot" "${DISK}"
fi
sgdisk -n 2:0:+"${BOOT_SIZE}" -t 2:8300 -c 2:"boot"       "${DISK}"
sgdisk -n 3:0:0               -t 3:8300 -c 3:"cryptlvm"   "${DISK}"

settle
wait_block "$P2"; wait_block "$P3"; [ "$BOOT_MODE" = "uefi" ] && wait_block "$P1" || true

###===================== FORMAT UNENCRYPTED ==================================
echo ">>> Formatting EFI/BIOS and /boot"
[ "${BOOT_MODE}" = "uefi" ] && mkfs.vfat -F32 -n EFI "$P1"
mkfs."${FS_BOOT}" -F -L BOOT "$P2"

###===================== LUKS + LVM ==========================================
echo ">>> Creating LUKS on $P3"
cryptsetup luksFormat "$P3"
cryptsetup open "$P3" "$MAP"
wait_block "/dev/mapper/${MAP}"

pvcreate "/dev/mapper/${MAP}"
vgcreate "${VG}" "/dev/mapper/${MAP}"

lvcreate -L "${LV_ROOT_SIZE}"          -n root            "${VG}"
lvcreate -L "${LV_HOME_SIZE}"          -n home            "${VG}"
lvcreate -L "${LV_VAR_SIZE}"           -n var             "${VG}"
lvcreate -L "${LV_VAR_LOG_SIZE}"       -n var_log         "${VG}"
lvcreate -L "${LV_VAR_LOG_AUDIT_SIZE}" -n var_log_audit   "${VG}"
lvcreate -L "${LV_TMP_SIZE}"           -n tmp             "${VG}"
lvcreate -L "${LV_VAR_TMP_SIZE}"       -n var_tmp         "${VG}"
[ -n "${LV_SWAP_SIZE}" ] && lvcreate -L "${LV_SWAP_SIZE}" -n swap "${VG}" || true

mkfs."${FS_DATA}" -F -L ROOT          "/dev/${VG}/root"
mkfs."${FS_DATA}" -F -L HOME          "/dev/${VG}/home"
mkfs."${FS_DATA}" -F -L VAR           "/dev/${VG}/var"
mkfs."${FS_DATA}" -F -L VAR_LOG       "/dev/${VG}/var_log"
mkfs."${FS_DATA}" -F -L VAR_LOG_AUDIT "/dev/${VG}/var_log_audit"
mkfs."${FS_DATA}" -F -L TMP           "/dev/${VG}/tmp"
mkfs."${FS_DATA}" -F -L VARTMP        "/dev/${VG}/var_tmp"
[ -n "${LV_SWAP_SIZE}" ] && mkswap -L SWAP "/dev/${VG}/swap" || true

###===================== MOUNT TARGET =========================================
mount "/dev/${VG}/root" "${MNT}"
mkdir -p "${MNT}/boot" "${MNT}/home" "${MNT}/var" "${MNT}/tmp" \
         "${MNT}/var/tmp" "${MNT}/var/log" "${MNT}/var/log/audit"
mount "$P2" "${MNT}/boot"
if [ "${BOOT_MODE}" = "uefi" ]; then
  mkdir -p "${MNT}/boot/efi"
  mount "$P1" "${MNT}/boot/efi"
fi
mount "/dev/${VG}/home"           "${MNT}/home"
mount "/dev/${VG}/var"            "${MNT}/var"
mount "/dev/${VG}/var_log"        "${MNT}/var/log"
mount "/dev/${VG}/var_log_audit"  "${MNT}/var/log/audit"
mount "/dev/${VG}/tmp"            "${MNT}/tmp"
mount "/dev/${VG}/var_tmp"        "${MNT}/var/tmp"
[ -n "${LV_SWAP_SIZE}" ] && swapon "/dev/${VG}/swap" || true

###===================== PRE-SEED CONFIGS =====================================
mkdir -p "${MNT}/etc/apk" "${MNT}/etc/conf.d" "${MNT}/etc/network"
cat > "${MNT}/etc/apk/repositories" <<EOF
${APK_REPO}
${APK_REPO_COMMUNITY}
EOF

# luks auto-open
cat > "${MNT}/etc/luks-open.conf" <<EOF
luks_main ${P3}
EOF

# fstab with hardened options
cat > "${MNT}/etc/fstab" <<EOF
# <fs>                         <mount>           <type>   <opts>                      <dump> <pass>
/dev/mapper/${VG}-root         /                 ${FS_DATA}  ${ROOT_OPTS}              0 1
${P2}                          /boot             ${FS_BOOT}  ${BOOT_OPTS}              0 2
$( [ "${BOOT_MODE}" = "uefi" ] && echo "${P1}                          /boot/efi         vfat      ${EFI_OPTS}                 0 2" )
/dev/mapper/${VG}-home         /home             ${FS_DATA}  ${HOME_OPTS}              0 2
/dev/mapper/${VG}-var          /var              ${FS_DATA}  ${VAR_OPTS}               0 2
/dev/mapper/${VG}-var_log      /var/log          ${FS_DATA}  ${VAR_LOG_OPTS}           0 2
/dev/mapper/${VG}-var_log_audit /var/log/audit   ${FS_DATA}  ${VAR_LOG_AUDIT_OPTS}     0 2
/dev/mapper/${VG}-tmp          /tmp              ${FS_DATA}  ${TMP_OPTS}               0 2
/dev/mapper/${VG}-var_tmp      /var/tmp          ${FS_DATA}  ${VAR_TMP_OPTS}           0 2
$( [ -n "${LV_SWAP_SIZE}" ] && echo "/dev/mapper/${VG}-swap          none              swap      defaults                  0 0" )
EOF

# identity / locale
echo "${HOSTNAME}" > "${MNT}/etc/hostname"
echo "${TIMEZONE}" > "${MNT}/etc/timezone"
cat > "${MNT}/etc/conf.d/keymaps" <<EOF
keymap="${KEYMAP}"
EOF

# simple networking
if [ "${USE_DHCP}" = "yes" ]; then
  cat > "${MNT}/etc/network/interfaces" <<EOF
auto lo
iface lo inet loopback

auto ${NET_IFACE}
iface ${NET_IFACE} inet dhcp
EOF
else
  cat > "${MNT}/etc/network/interfaces" <<EOF
auto lo
iface lo inet loopback

auto ${NET_IFACE}
iface ${NET_IFACE} inet static
    address ${STATIC_IP}
    gateway ${STATIC_GW}
    dns ${STATIC_DNS}
EOF
fi

###===================== INSTALL BASE SYSTEM ==================================
apk add --no-progress alpine-conf
setup-disk -m sys "${MNT}"

###===================== CHROOT CONFIG ========================================
mount -t proc none "${MNT}/proc"
mount -t sysfs none "${MNT}/sys"
mount -o bind /dev "${MNT}/dev"
mount -o bind /run "${MNT}/run"

cat > "${MNT}/root/post-chroot.sh" <<'EOS'
set -euo pipefail
apk update
apk add cryptsetup lvm2 mkinitfs e2fsprogs openrc busybox-initscripts
apk add grub grub-efi efibootmgr || true
apk add openssh doas sudo tzdata || true
apk add audit || true   # auditd

# timezone
setup-timezone -z "$(cat /etc/timezone 2>/dev/null || echo UTC)" || true

# initramfs features
if grep -q '^features=' /etc/mkinitfs/mkinitfs.conf 2>/dev/null; then
  sed -i 's/^features=.*/features="base cryptsetup lvm"/' /etc/mkinitfs/mkinitfs.conf
else
  echo 'features="base cryptsetup lvm"' > /etc/mkinitfs/mkinitfs.conf
fi
mkinitfs

# ensure audit log dir perms
install -d -m 0700 /var/log/audit

# kernel cmdline: enable early auditing
if [ -f /etc/default/grub ]; then
  if grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
    sed -i 's/^GRUB_CMDLINE_LINUX="\([^"]*\)"/GRUB_CMDLINE_LINUX="\1 audit=1"/' /etc/default/grub
  else
    echo 'GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
  fi
fi

# passwords & users
if [ -f /root/.rootpw ]; then
  echo "root:$(cat /root/.rootpw)" | chpasswd
  rm -f /root/.rootpw
fi
if [ -f /root/.newuser ]; then
  u="$(cut -d: -f1 /root/.newuser)"; p="$(cut -d: -f2- /root/.newuser)"
  adduser -D -G wheel "$u"
  echo "${u}:${p}" | chpasswd
  rm -f /root/.newuser
fi

# sudo/doas
if command -v doas >/dev/null 2>&1; then
  mkdir -p /etc/doas.d
  echo 'permit persist :wheel' > /etc/doas.d/wheel.conf
else
  sed -i 's/^# \(%wheel ALL=(ALL:ALL) ALL\)/\1/' /etc/sudoers
fi

# SSH
rc-update add networking boot || true
rc-update add sshd default || true
rc-update add crond default || true
if [ -f /etc/ssh/sshd_config ]; then
  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
fi

# SSH keys
if [ -f /root/.authkey ]; then
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  cat /root/.authkey >> /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
fi
if [ -f /home/.userauth ]; then
  u="$(cut -d: -f1 /home/.userauth)"
  mkdir -p "/home/${u}/.ssh" && chmod 700 "/home/${u}/.ssh"
  sed -e "s/^${u}://" /home/.userauth >> "/home/${u}/.ssh/authorized_keys"
  chmod 600 "/home/${u}/.ssh/authorized_keys"
  chown -R "${u}:${u}" "/home/${u}/.ssh"
  rm -f /home/.userauth
fi

# Bootloader
if [ -d /sys/firmware/efi/efivars ]; then
  grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=alpine
else
  TARGET_DISK="$(lsblk -no pkname / | head -n1)"
  [ -z "$TARGET_DISK" ] && TARGET_DISK="$(lsblk -ndo pkname /dev/mapper/$(ls /dev/mapper | grep -m1 -E 'vg0-root|luks_main') 2>/dev/null | head -n1)"
  [ -n "$TARGET_DISK" ] && grub-install --target=i386-pc "/dev/${TARGET_DISK}" || grub-install --target=i386-pc /dev/sda
fi
grub-mkconfig -o /boot/grub/grub.cfg

# services
rc-update add hwclock boot || true
rc-update add killprocs shutdown || true
rc-update add savecache shutdown || true
rc-update add auditd default || true

echo "Post-chroot config complete."
EOS
chmod +x "${MNT}/root/post-chroot.sh"

# secrets to chroot
printf "%s" "${ROOT_PASSWORD}" > "${MNT}/root/.rootpw"
if [ -n "${NEW_USER}" ]; then
  printf "%s:%s" "${NEW_USER}" "${NEW_USER_PASSWORD}" > "${MNT}/root/.newuser"
fi
if [ -n "${AUTHORIZED_KEY}" ]; then
  printf "%s\n" "${AUTHORIZED_KEY}" > "${MNT}/root/.authkey"
  if [ -n "${NEW_USER}" ]; then
    printf "%s:%s\n" "${NEW_USER}" "${AUTHORIZED_KEY}" > "${MNT}/home/.userauth"
  fi
fi

chroot "${MNT}" /bin/sh -c "/root/post-chroot.sh"
rm -f "${MNT}/root/post-chroot.sh"

###===================== SSH & POLICY TWEAKS ==================================
if [ "${ENABLE_SSH}" != "yes" ]; then
  chroot "${MNT}" rc-update del sshd default || true
fi
if [ "${PERMIT_ROOT_SSH}" = "yes" ] && [ -f "${MNT}/etc/ssh/sshd_config" ]; then
  sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' "${MNT}/etc/ssh/sshd_config"
fi

###===================== CLEANUP & SUMMARY ====================================
umount -R "${MNT}/proc" || true
umount -R "${MNT}/sys" || true
umount -R "${MNT}/dev" || true
umount -R "${MNT}/run" || true

echo
echo "============================================================================"
echo "All done. Installed Alpine with:"
echo "- ${BOOT_MODE^^} boot, /boot$( [ "${BOOT_MODE}" = "uefi" ] && echo " + /boot/efi") unencrypted"
echo "- LUKS -> LVM: /, /home, /var, /var/log, /var/log/audit, /tmp, /var/tmp $( [ -n "${LV_SWAP_SIZE}" ] && echo "+ swap")"
echo "- Hardened mount options on tmp, var/tmp, var/log, var/log/audit"
echo "- Audit enabled (auditd + kernel audit=1)"
echo "- Hostname: ${HOSTNAME}, TZ: ${TIMEZONE}, Keymap: ${KEYMAP}"
echo "- User: ${NEW_USER:-<none>}   SSH: ${ENABLE_SSH}   Root SSH: ${PERMIT_ROOT_SSH}"
echo "Now: reboot, enter LUKS passphrase, and log in."
echo "============================================================================"
