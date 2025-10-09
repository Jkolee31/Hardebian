#!/usr/bin/env bash

set -euo pipefail

# PRE CONFIG/AUDIT
echo 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
echo 'APT::Get::AllowUnauthenticated "false";' >> /etc/apt/apt.conf.d/98-hardening
echo 'Acquire::http::AllowRedirect "false";' >> /etc/apt/apt.conf.d/98-hardening
echo 'APT::Install-Recommends "false";' >> /etc/apt/apt.conf.d/98-hardening 
apt update

git clone https://github.com/ovh/debian-cis.git && cd debian-cis
cp debian/default /etc/default/cis-hardening
sed -i "s#CIS_LIB_DIR=.*#CIS_LIB_DIR='$(pwd)'/lib#" /etc/default/cis-hardening
sed -i "s#CIS_CHECKS_DIR=.*#CIS_CHECKS_DIR='$(pwd)'/bin/hardening#" /etc/default/cis-hardening
sed -i "s#CIS_CONF_DIR=.*#CIS_CONF_DIR='$(pwd)'/etc#" /etc/default/cis-hardening
sed -i "s#CIS_TMP_DIR=.*#CIS_TMP_DIR='$(pwd)'/tmp#" /etc/default/cis-hardening
sed -i "s#CIS_VERSIONS_DIR=.*#CIS_VERSIONS_DIR='$(pwd)'/versions#" /etc/default/cis-hardening
./bin/hardening/1.1.1.1_disable_freevxfs.sh --audit
bin/hardening.sh --audit-all --allow-unsupported-distribution
bin/hardening.sh --set-hardening-level 5 --allow-unsupported-distribution
bin/hardening.sh --apply --allow-unsupported-distribution
bin/hardening.sh --apply --allow-unsupported-distribution
bin/hardening.sh --apply --allow-unsupported-distribution

apt purge virtualbox* lxc* docker* podman* xen* bochs* uml-utilities vagrant* ssh* openssh* acpi* anacron* samba winbind qemu-system* qemu-utils libvirt* virt-manager cron* avahi* cup* zram* print* rsync* virtual* sane* rpc* bind* nfs* blue* pp* mesa* spee* espeak* mobile* wireless* bc perl blue* inet* python3 apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra dictionaries-common doc-debian emacsen-common ethtool iamerican ibritish ienglish-common inetutils-telnet ispell task-english util-linux-locales wamerican wtmpdb zerofree tasksel tasksel-data vim-tiny vim-common

install -d /etc/apt/preferences.d
cat >/etc/apt/preferences.d/deny-ssh.pref <<'EOF'
Package: openssh* ssh* libssh*
Pin: release *
Pin-Priority: -1

Package: dropbear
Pin: release *
Pin-Priority: -1

Package: tinyssh
Pin: release *
Pin-Priority: -1

Package: qemu* libvirt* virtualbox* lxc* docker* podman* xen* vagrant*
Pin: release *
Pin-Priority: -1

Package: systemd
Pin: release *
Pin-Priority: -1

Package: libsystemd0
Pin: release *
Pin-Priority: -1

Package: libpam-systemd
Pin: release *
Pin-Priority: -1

Package: systemd-sysv
Pin: release *
Pin-Priority: -1

Package: systemd-container
Pin: release *
Pin-Priority: -1

Package: systemd-timesyncd
Pin: release *
Pin-Priority: -1

EOF
apt update

systemctl mask --now ssh.service ssh.socket 2>/dev/null || true
systemctl mask --now sshd.service 2>/dev/null || true

header "sudoers"
  run "install -d -m 750 /etc/sudoers.d"
  bak /etc/sudoers
  local f="/etc/sudoers.d/99-hardening"
  cat >"$f" <<'EOF'
Defaults passwd_tries=2
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
  run "touch /var/log/sudo.log && chmod 0600 /var/log/sudo.log"
  run "visudo -cf /etc/sudoers"
  run "visudo -cf $f"

apt install -y  pamu2fcfg libpam-u2f apparmor rsyslog chrony apparmor-utils apparmor-profiles apparmor-profiles-extra apt-listbugs apt-listchanges needrestart debsecan debsums acct wget gnupg lsb-release apt-transport-https unzip patch pulseaudio pulseaudio-utils pavucontrol alsa-utils rkhunter chkrootkit lynis macchanger unhide tcpd haveged lsb-release apt-transport-https auditd fonts-liberation extrepo gnome-terminal gnome-brave-icon-theme breeze-gtk-theme bibata* tcpd macchanger mousepad libxfce4ui-utils thunar xfce4-panel xfce4-session xfce4-settings xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulse* xfce4-whisk* opensnitch* python3-opensnitch*

#U2F
mkdir /home/dev/.config
-u dev pamu2fcfg  > /home/dev/.config/default
chmod 600 /home/dev/.config/default
install -o root -g root -m 600 /home/dev/.config/default /etc/conf
addgroup wheel
install -d /etc/sudoers.d
echo "%wheel  ALL=(ALL) ALL" >/etc/sudoers.d/00-wheel
chmod 440 /etc/sudoers.d/00-wheel
adduser dev wheel

#PAM
ts="$(date +%Y%m%d%H%M%S)"

backup() {
  local f="$1"
  if [[ -f "$f" ]]; then
    cp -a "$f" "${f}.bak.${ts}"
    echo "backup: ${f} -> ${f}.bak.${ts}"
  fi
}

write() {
  local f="$1"
  shift
  install -m 0644 -o root -g root /dev/null "$f"
  cat >"$f" <<<"$*"
  echo "wrote: $f"
}

backup /etc/pam.d/common-auth
write  /etc/pam.d/common-auth "#%PAM-1.0
auth    required pam_u2f.so authfile=/etc/conf cue userverification=required max_retries=3
auth    requisite pam_deny.so
auth    required  pam_permit.so
"
sudo_drop=/etc/sudoers.d/require-touch
tmp_drop=$(mktemp)

cat >"$tmp_drop" <<'EOF'
# Require a fresh auth for every use (no caching)
Defaults timestamp_timeout=0
EOF

backup /etc/pam.d/common-account
write  /etc/pam.d/common-account "#%PAM-1.0
account required pam_unix.so
"

backup /etc/pam.d/common-session
write  /etc/pam.d/common-session "#%PAM-1.0
session required pam_limits.so
session required pam_env.so
session optional pam_systemd.so
session optional pam_umask.so umask=077
session required pam_unix.so
"

backup /etc/pam.d/common-session-noninteractive
write  /etc/pam.d/common-session-noninteractive "#%PAM-1.0
session required pam_limits.so
session required pam_env.so
session optional pam_systemd.so
session optional pam_umask.so umask=077
session required pam_unix.so
"

backup /etc/pam.d/common-password
write  /etc/pam.d/common-password "#%PAM-1.0
password [success=1 default=ignore] pam_unix.so yescrypt use_authtok
password requisite pam_deny.so
password required  pam_permit.so
"

backup /etc/pam.d/login
write  /etc/pam.d/login "#%PAM-1.0
auth    requisite pam_securetty.so
auth    include   common-auth
account include   common-account
password include  common-password
session include   common-session
"

backup /etc/pam.d/sudo
write  /etc/pam.d/"#%PAM-1.0
auth    include   common-auth
account required  pam_unix.so
session required  pam_env.so
session required  pam_limits.so
"

backup /etc/pam.d/sudo-i
write  /etc/pam.d/sudo-i "#%PAM-1.0
auth    include   common-auth
account required  pam_unix.so
session required  pam_env.so
session required  pam_limits.so
"

backup /etc/pam.d/su
write  /etc/pam.d/su "#%PAM-1.0
auth    include   common-auth
account required  pam_unix.so
session required  pam_env.so
session required  pam_unix.so
"

backup /etc/pam.d/su-l
write  /etc/pam.d/su-l "#%PAM-1.0
auth    include   common-auth
account required  pam_unix.so
session required  pam_env.so
session required  pam_unix.so
"

backup /etc/pam.d/other
write  /etc/pam.d/other "#%PAM-1.0
auth    required pam_deny.so
account required pam_deny.so
password required pam_deny.so
session required pam_deny.so
"

backup /etc/pam.d/lightdm || true
write  /etc/pam.d/lightdm "#%PAM-1.0
auth    requisite pam_nologin.so
auth    include   common-auth
account include   common-account
session include   common-session
password include  common-password
"
chattr +i -R /etc/pam.d/*

# FIREWALL
cat >/etc/nftables.conf <<EOF
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    iifname "wg0" accept
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
  }

  chain output {
    type filter hook output priority filter; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    udp dport 51820 accept
    udp dport 53 accept
    tcp dport 443 accept
    tcp dport 80 accept

  }
}

EOF
nft -f /etc/nftables.conf
chattr +i /etc/nftables.conf

#GROUP/USER
groupdel avahi --force
groupdel _flatpak --force
groupdel _ssh --force
groupdel bluetooth --force
groupdel irc --force
groupdel kvm --force
groupdel nm-openconnect --force
groupdel nm-openvpn --force
groupdel sambashare --force
groupdel scanner --force
groupdel voice --force
groupdel vboxsf --force
groupdel games --force
groupdel colord --force
userdel sshd
userdel colord
userdel hplip
userdel _flatpak
userdel statd
userdel dnsmasq
userdel _rpc
userdel avahi
userdel usbmux
userdel tss
userdel nobody
userdel irc
userdel games

# MISC HARDENING 
touch /etc/securetty
chown  root:root /etc/securetty
chmod  400 /etc/securetty
echo "console" >  etc/securetty
echo "/bin/bash" > /etc/shells
passwd -l root
echo "needs_root_rights=no" >> /etc/X11/Xwrapper.config
dpkg-reconfigure xserver-xorg-legacy
echo "multi on
      order hosts" > /etc/host.conf

sed -i 's/^# End of file*//' /etc/security/limits.conf
 { echo '*     hard  maxlogins 1'
   echo 'root  hard  maxlogins 5'
   echo '*     hard  core 0'
   echo '*     soft  core  0'
   echo '*     hard  nproc 225'
   echo '*     soft  nproc 225'   
   echo '# End of file'
  } >> /etc/security/limits.conf
  echo "ProcessSizeMax=0
  Storage=none" >> /etc/systemd/coredump.conf
  echo "ulimit -c 0" >> /etc/profile

sed -i -e 's/^DIR_MODE=.*/DIR_MODE=0750/' -e 's/^#DIR_MODE=.*/DIR_MODE=0750/' /etc/adduser.conf
sed -i -e 's/^DSHELL=.*/DSHELL=\/usr\/sbin\/nologin/' -e 's/^#DSHELL=.*/DSHELL=\/bin\/false/' /etc/adduser.conf
sed -i -e 's/^USERGROUPS=.*/USERGROUPS=yes/' -e 's/^#USERGROUPS=.*/USERGROUPS=yes/' /etc/adduser.conf
sed -i 's/^SHELL=.*/SHELL=\/usr\/sbin\/nologin/' /etc/default/useradd
sed -i 's/^# INACTIVE=.*/INACTIVE=30/' /etc/default/useradd
sed -i 's/^.*LOG_OK_LOGINS.*/LOG_OK_LOGINS yes/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs
sed -i 's/DEFAULT_HOME.*/DEFAULT_HOME no/' /etc/login.defs
sed -i 's/ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs
sed -i 's/USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' /etc/login.defs
sed -i 's/umask 077/umask 027/g' /etc/init.d/rc
echo "umask 077" >> /etc/profile
echo "umask 077" >> /etc/bash.bashrc
echo "umask 077" >>/etc/login.defs
echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny
 
# GRUB
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality mce=0 quiet loglevel=0 ipv6.disable=1 spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force quiet loglevel=0 apparmor=1 security=apparmor"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub 
chattr +i /etc/default/grub

# MESSAGE
echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" >> /etc/motd  
  
echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" >> /etc/issue
  
echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" >> /etc/issue.net

# MODULES
cat > /etc/modprobe.d/harden.conf << 'EOF'
blacklist kvm
blacklist kvm_intel
blacklist kvm_amd
blacklist vboxdrv
blacklist vboxnetflt
blacklist vboxnetadp
blacklist vmw_vmci
blacklist vmmon
blacklist xen
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
install cifs /bin/false
install nfs /bin/false
install nfsd /bin/false
install nfsv3 /bin/false
install nfsv4 /bin/false
install lockd /bin/false
install ksmbd /bin/false
install gfs2 /bin/false
install bluetooth /bin/false
install btusb /bin/false
install uvcvideo /bin/false
install firewire-core /bin/false
install thunderbolt /bin/false
install usb-storage /bin/false
EOF

# KERNEL
rm -r /etc/sysctl.d
rm -r /usr/lib/sysctl.d
echo "dev.tty.ldisc_autoload=0
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 3
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16" > /etc/sysctl.conf
sysctl --system

# MOUNTS
echo "
/dev/mapper/lvg-root                      /                          ext4       discard,noatime,nodev,errors=remount-ro 0 1
/dev/mapper/lvg-home                      /home                      ext4       discard,noatime,nodev,nosuid 0 2
/dev/mapper/lvg-tmp                       /tmp                       ext4       discard,noatime,nodev,nosuid 0 2
/dev/mapper/lvg-usr                       /usr                       ext4       discard,noatime,nodev,ro 0 2
/dev/mapper/lvg-usr--local                /usr/local                 ext4       discard,noatime,nodev 0 2
/dev/mapper/lvg-var                       /var                       ext4       discard,noatime,nodev,nosuid 0 2
/dev/mapper/lvg-var--log                  /var/log                   ext4       discard,noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-var--tmp                  /var/tmp                   ext4       discard,noatime,nodev,nosuid 0 2
udev                                      /dev                       devtmpfs   nosuid,noexec,noatime 0 0  
devpts                                    /dev/pts                   devpts     nosuid,noexec,noatime,newinstance,ptmxmode=0666 0 0 
tmpfs                                     /home/dev/.cache           tmpfs      nosuid,nodev,noexec,uid=1000,gid=1000,mode=700 0 0
proc                                      /proc                      proc       nosuid,nodev,noexec,hidepid=2 0 0
securityfs                                /sys/kernel/security       securityfs nosuid,nodev,noexec 0 0
pstore                                    /sys/fs/pstore             pstore     nosuid,nodev,noexec 0 0
systemd                                   /sys/fs/cgroup/systemd     cgroup     nosuid,nodev,noexec 0 0
cgroup                                    /sys/fs/cgroup             tmpfs      nosuid,nodev,noexec 0 0
efivarfs                                  /sys/firmware/efi/efivars  efivarfs   nosuid,nodev,noexec 0 0
net_cls                                   /sys/fs/cgroup/net_cls     cgroup     nosuid,nodev,noexec 0 0
tmpfs                                     /run                       tmpfs      nosuid,nodev,noexec,mode=0755 0 0
tmpfs                                     /dev/shm                   tmpfs      nosuid,noexec,mode=1777 0 0
tmpfs                                     /tmp                       tmpfs      nosuid,nodev,noexec,mode=1777 0 0
tmpfs                                     /var/tmp                   tmpfs      nosuid,nodev,noexec,mode=1777 0 0
" >> /etc/fstab

# LOCKDOWN
find / -perm -4000 -o -perm -2000 -exec chmod a-s {} \; 2>/dev/null
find / -perm -4000 -exec chmod u-s {} \;
find / -perm -4000 -exec chmod g-s {} \;
find / -perm -2000 -exec chmod u-s {} \;
find / -perm -2000 -exec chmod g-s {} \;
chmod u+s /usr/bin/sudo
chmod o-rx /usr/bin/as
chattr +i /etc/fstab
chattr +i /etc/adduser.conf
chattr +i /etc/group
chattr +i /etc/group-
chattr +i /etc/hosts
chattr +i /etc/host.conf
chattr +i /etc/hosts.allow
chattr +i /etc/hosts.deny
chattr +i /etc/login.defs
chattr -R +i /etc/default
chattr +i /etc/passwd
chattr +i /etc/passwd-
chattr +i /etc/securetty
chattr -R +i /etc/security
chattr +i /etc/gshadow-
chattr +i /etc/gshadow
chattr -R +i /etc/ssh
chattr -R +i /etc/sudoers.d
chattr +i /root/.bashrc
chattr +i /etc/shadow
chattr +i /etc/shadow-
chattr +i /etc/shells
chattr -R +i /etc/pam.d
chattr +i /etc/sysctl.conf
chattr -R +i /etc/modprobe.d
chattr +i /etc/services
chattr +i /etc/sudoers
