#!/usr/bin/env bash

set -euo pipefail

# PRE CONFIG
cat >/etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";
EOF

cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

cat >/etc/apt/apt.conf.d/98-hardening <<'EOF'
APT::Get::AllowUnauthenticated "false";
Acquire::http::AllowRedirect "false";
APT::Install-Recommends "false";
EOF
apt update

# FIREWALL
apt install -y iptables iptables-persistent netfilter-persistent
systemctl enable netfilter-persistent
service netfilter-persistent start
iptables -F
iptables -X
iptables -Z
iptables -t nat -F
iptables -t nat -X
iptables -t nat -Z
iptables -t mangle -F
iptables -t mangle -X
iptables -t mangle -Z
iptables -N UDP
iptables -N TCP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP
iptables -A INPUT -p udp -j DROP
iptables -A INPUT -p tcp -j DROP
iptables -A INPUT -j DROP
iptables -A UDP -p udp --dport 53 -j ACCEPT
iptables -A TCP -p tcp --dport 443 -j ACCEPT
iptables -A TCP -p tcp --dport 80 -j ACCEPT
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
iptables-save   > /etc/iptables/rules.v4
ip6tables-save  > /etc/iptables/rules.v6
netfilter-persistent save

# DISABLE & MASK UNNECESSARY SERVICES
systemctl disable --now debug-shell.service wpa_supplicant speech-dispatcher bluez bluetooth.service apport.service avahi-daemon.socket avahi-daemon.service cups-browsed cups.socket cups.path cups.service nvmf-autoconnect.service nvmefc-boot-connections.service ModemManager.service usbmuxd.service usb_modeswitch@.service usb-gadget.target udisks2.service kexec.target systemd-kexec.service fprintd.service systemd-binfmt.service ctrl-alt-del.target rpcbind.target proc-sys-fs-binfmt_misc.mount proc-sys-fs-binfmt_misc.automount printer.target

# PACKAGE RESTRICTIONS
apt purge -y  zram* pci* pmount* acpi* anacron* avahi* bc bind9* dns* fastfetch fonts-noto* fprint* isc-dhcp* lxc* docker* podman* xen* bochs* uml* vagrant* libssh* ssh* openssh* acpi* samba* winbind* qemu* libvirt* virt* cron* avahi* cup* print* rsync* nftables* virtual* sane* rpc* bind* nfs* blue* pp* spee* espeak* mobile* wireless* bc perl inet* util-linux-locales tasksel* vim* os-prober* netcat* libssh* gcc* g++* gdb* lldb* strace* ltrace* as nasm yasm fasm build-essential automake autoconf libtool cmake ninja-build meson

install -d /etc/apt/preferences.d
cat >/etc/apt/preferences.d/deny-ssh.pref <<'EOF'
Package: openssh*
Pin: release *
Pin-Priority: -1

Package: dropbear*
Pin: release *
Pin-Priority: -1

Package: ssh*
Pin: release *
Pin-Priority: -1

Package: tinyssh*
Pin: release *
Pin-Priority: -1

Package: qemu*       
Pin: release *
Pin-Priority: -1

Package: libvirt*
Pin: release *
Pin-Priority: -1

Package: uml*
Pin: release *
Pin-Priority: -1

Package: virt*
Pin: release *
Pin-Priority: -1

Package: courier*
Pin: release *
Pin-Priority: -1

Package: dma*
Pin: release *
Pin-Priority: -1

Package: tripwire*
Pin: release *
Pin-Priority: -1

Package: avahi*
Pin: release *
Pin-Priority: -1

Package: samba*
Pin: release *
Pin-Priority: -1

Package: pmount*
Pin: release *
Pin-Priority: -1

Package: sane*
Pin: release *
Pin-Priority: -1

Package: netcat*
Pin: release *
Pin-Priority: -1

Package: os-prober*
Pin: release *
Pin-Priority: -1

Package: make*
Pin: release *
Pin-Priority: -1

Package: pp*
Pin: release *
Pin-Priority: -1

Package: blue*
Pin: release *
Pin-Priority: -1

Package: rpc*
Pin: release *
Pin-Priority: -1

Package: nfs*
Pin: release *
Pin-Priority: -1

Package: cup*
Pin: release *
Pin-Priority: -1

Package: anacron*
Pin: release *
Pin-Priority: -1

Package: exim*
Pin: release *
Pin-Priority: -1

Package: print*
Pin: release *
Pin-Priority: -1

Package: vagrant*
Pin: release *
Pin-Priority: -1

Package: lxc*
Pin: release *
Pin-Priority: -1

Package: docker*
Pin: release *
Pin-Priority: -1

Package: podman*
Pin: release *
Pin-Priority: -1

Package: xen*
Pin: release *
Pin-Priority: -1

Package: bochs*
Pin: release *
Pin-Priority: -1

Package: gnustep*
Pin: release *
Pin-Priority: -1

Package: sendmail*
Pin: release *
Pin-Priority: -1

Package: mobile*
Pin: release *
Pin-Priority: -1

Package: wireless*
Pin: release *
Pin-Priority: -1

Package: inet*
Pin: release *
Pin-Priority: -1

Package: nftables*
Pin: release *
Pin-Priority: -1

Package: gcc*
Pin: release *
Pin-Priority: -1

Package: g++*
Pin: release *
Pin-Priority: -1

Package: gdb*
Pin: release *
Pin-Priority: -1

Package: lldb*
Pin: release *
Pin-Priority: -1

Package: strace*
Pin: release *
Pin-Priority: -1

Package: ltrace*
Pin: release *
Pin-Priority: -1

Package: build-essential*
Pin: release *
Pin-Priority: -1

Package: automake*
Pin: release *
Pin-Priority: -1

Package: autoconf*
Pin: release *
Pin-Priority: -1

Package: cmake*
Pin: release *
Pin-Priority: -1

Package: nasm*
Pin: release *
Pin-Priority: -1

Package: yasm*
Pin: release *
Pin-Priority: -1
EOF

# INSTALL PACKAGES
apt install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra pamu2fcfg libpam-u2f rsyslog chrony libpam-tmpdir fail2ban needrestart apt-listchanges acct sysstat rkhunter chkrootkit debsums apt-show-versions unzip patch alsa-utils pipewire pipewire-audio-client-libraries pipewire-pulse wireplumber lynis macchanger unhide tcpd fonts-liberation extrepo gnome-brave-icon-theme breeze-gtk-theme bibata* mousepad xfce4 libxfce4ui-utils thunar xfce4-panel xfce4-session xfce4-settings xfce4-terminal xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulse* xfce4-whisk* opensnitch* python3-opensnitch* auditd audispd-plugins unattended-upgrades
systemctl enable apparmor
systemctl start apparmor
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# AUDITD CONFIGURATION
cat >/etc/audit/rules.d/hardening.rules <<'EOF'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (2 = panic on failure)
-f 2

# Audit changes to time
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Audit identity/authentication events
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Audit PAM configuration
-w /etc/pam.d/ -p wa -k pam
-w /etc/nsswitch.conf -p wa -k identity

# Audit login/logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Audit network environment
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network

# Audit AppArmor events
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor

# Audit kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Audit file deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete

# Audit sudo usage
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Audit changes to system mandatory access controls
-w /etc/selinux/ -p wa -k MAC-policy

# Audit session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Audit discretionary access control permission modifications
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Audit privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Make config immutable
-e 2
EOF

systemctl enable auditd
systemctl start auditd

# PAM/U2F
echo "============================================"
echo "CRITICAL: U2F KEY ENROLLMENT"
echo "============================================"
echo "Insert your U2F key and touch it when prompted."
echo "If this fails, the system will be LOCKED OUT."
echo "Press Enter to continue or Ctrl+C to abort..."
read -r
pamu2fcfg -u dev > /etc/conf
if [ ! -s /etc/conf ]; then
    echo "ERROR: U2F enrollment failed! Aborting to prevent lockout."
    rm -f /etc/conf
    exit 1
fi
echo "U2F enrollment successful. Key stored in /etc/conf"
chmod 600 /etc/conf
chown root:root /etc/conf
# Don't make immutable yet - let user test login first
echo "WARNING: Test your U2F login before running the lockdown section!"
echo "The file will be made immutable at the end of the script."

cat >/etc/pam.d/chfn <<'EOF'
#%PAM-1.0
auth      sufficient  pam_rootok.so
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat >/etc/pam.d/chpasswd <<'EOF'
#%PAM-1.0
password  include     common-password
EOF

cat >/etc/pam.d/chsh <<'EOF'
#%PAM-1.0
auth      required    pam_shells.so
auth      sufficient  pam_rootok.so
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat >/etc/pam.d/common-account <<'EOF'
#%PAM-1.0
account   required    pam_unix.so
EOF

cat >/etc/pam.d/common-password <<'EOF'
#%PAM-1.0
password  [success=1  default=ignore]  pam_unix.so obscure use_authtok try_first_pass yescrypt
password  requisite   pam_deny.so
EOF

cat >/etc/pam.d/common-auth <<'EOF'
#%PAM-1.0
auth      sufficient  pam_u2f.so authfile=/etc/conf
auth      requisite   pam_deny.so
EOF

cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
session   required    pam_unix.so
EOF

cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
session   required    pam_unix.so
EOF

cat >/etc/pam.d/sudo <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/conf
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/sudo-i <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/conf
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/sshd <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/conf
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/su <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/conf
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/su-l <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/conf
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/other <<'EOF'
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF

cat >/etc/pam.d/login <<'EOF'
#%PAM-1.0
auth      optional    pam_faildelay.so delay=3000000
auth      requisite   pam_nologin.so
auth      required    pam_u2f.so authfile=/etc/conf
account   required    pam_access.so
session   required    pam_limits.so
account   include     common-account
session   include     common-session
password  include     common-password
EOF

cat >/etc/pam.d/lightdm <<'EOF'
#%PAM-1.0
auth      requisite   pam_nologin.so
auth      required    pam_u2f.so authfile=/etc/conf
account   include     common-account
session   [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close
session   include     common-session
session   [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open
password  include     common-password
EOF

cat >/etc/pam.d/lightdm-greeter <<'EOF'
#%PAM-1.0
auth      requisite   pam_nologin.so
account   include     common-account
password  include     pam_unix.so
session   optional    pam_systemd.so
session   include     common-session
EOF

cat >/etc/pam.d/newusers <<'EOF'
#%PAM-1.0
password  include     common-password
EOF

cat >/etc/pam.d/passwd <<'EOF'
#%PAM-1.0
password  include     common-password
EOF

cat >/etc/pam.d/runuser <<'EOF'
#%PAM-1.0
auth	    sufficient  pam_rootok.so
session	  required    pam_limits.so
session	  required    pam_unix.so
EOF

cat >/etc/pam.d/runuser-l <<'EOF'
#%PAM-1.0
auth	    include     runuser
session	  include     runuser
EOF

# OVH HARDENING SCRIPT
apt install -y git
git clone https://github.com/ovh/debian-cis.git && cd debian-cis
cp debian/default /etc/default/cis-hardening
sed -i "s#CIS_LIB_DIR=.*#CIS_LIB_DIR='$(pwd)'/lib#" /etc/default/cis-hardening
sed -i "s#CIS_CHECKS_DIR=.*#CIS_CHECKS_DIR='$(pwd)'/bin/hardening#" /etc/default/cis-hardening
sed -i "s#CIS_CONF_DIR=.*#CIS_CONF_DIR='$(pwd)'/etc#" /etc/default/cis-hardening
sed -i "s#CIS_TMP_DIR=.*#CIS_TMP_DIR='$(pwd)'/tmp#" /etc/default/cis-hardening
sed -i "s#CIS_VERSIONS_DIR=.*#CIS_VERSIONS_DIR='$(pwd)'/versions#" /etc/default/cis-hardening
bin/hardening.sh --audit-all --allow-unsupported-distribution
bin/hardening.sh --set-hardening-level 5 --allow-unsupported-distribution
rm /home/dev/debian-cis/bin/hardening/disable_print_server.sh
rm /home/dev/debian-cis/bin/hardening/disable_avahi_server.sh
rm /home/dev/debian-cis/bin/hardening/disable_xwindow_system.sh
rm /home/dev/debian-cis/bin/hardening/install_tripwire.sh
rm /home/dev/debian-cis/bin/hardening/install_syslog-ng.sh
bin/hardening.sh --apply --allow-unsupported-distribution
bin/hardening.sh --apply --allow-unsupported-distribution
bin/hardening.sh --apply --allow-unsupported-distribution

# SUDO
cat >/etc/sudoers <<'EOF'
Defaults passwd_tries=2
Defaults use_pty
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root  ALL=(ALL) ALL
%sudo ALL=(ALL) ALL
EOF
chmod 0440 /etc/sudoers
chmod 0440 /etc/sudoers.d

# MAC ADDRESS RANDOMIZATION
cat >/etc/systemd/system/macspoof.service <<'EOF'
[Unit]
Description=Randomize MAC address
Wants=network-pre.target
Before=network-pre.target
BindsTo=sys-subsystem-net-devices-eth0.device
After=sys-subsystem-net-devices-eth0.device

[Service]
Type=oneshot
ExecStart=/usr/bin/macchanger -r eth0
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable macspoof.service

# MISC HARDENING
echo "/bin/bash" > /etc/shells
passwd -l root
echo "needs_root_rights=no" >> /etc/X11/Xwrapper.config
dpkg-reconfigure xserver-xorg-legacy

cat >/etc/host.conf <<'EOF'
order hosts,bind
multi on
EOF

cat >/etc/security/limits.d/limits.conf <<'EOF'
*     hard  core       0
*     hard  nproc      200
*     hard  nofile     1024
*     soft  nofile     512
*     -     maxlogins  2
root  -     maxlogins  5
root  hard  nproc      3000
EOF

echo "ProcessSizeMax=0
Storage=none" >> /etc/systemd/coredump.conf
echo "ulimit -c 0" >> /etc/profile

sed -i 's/^#\?REMOVE_HOME.*/REMOVE_HOME = yes/' /etc/deluser.conf
sed -i 's/^#\?REMOVE_ALL_FILES.*/REMOVE_ALL_FILES = yes/' /etc/deluser.conf
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 10/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs
sed -i 's/^UID_MIN.*/UID_MIN 1000/' /etc/login.defs
sed -i 's/^UID_MAX.*/UID_MAX 60000/' /etc/login.defs
sed -i 's/^CREATE_HOME.*/CREATE_HOME yes/' /etc/login.defs
sed -i 's/^CHFN_RESTRICT.*/CHFN_RESTRICT /' /etc/login.defs
sed -i "/^SHELL=/ s/=.*\+/=\/usr\/sbin\/nologin/" /etc/default/useradd
sed -i "/^DSHELL=/ s/=.*\+/=\/usr\/sbin\/nologin/" /etc/adduser.conf
echo "UMASK 077" >> /etc/login.defs
echo "umask 077" >> /etc/profile
echo "umask 077" >> /etc/bash.bashrc
echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny

cat > /etc/profile.d/autologout.sh <<'EOF'
TMOUT=300
readonly TMOUT
export TMOUT
EOF

cat > /etc/security/access.conf << 'EOF'
-:ALL EXCEPT dev:tty1
-:ALL EXCEPT dev:LOCAL
-:dev:ALL EXCEPT LOCAL
+:dev:tty1 tty2 tty3
-:root:ALL
-:ALL:ALL
EOF

# GRUB
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge init_on_alloc=1 init_on_free=1 page_poison=1 random.trust_cpu=off random.trust_bootloader=off pti=on page_alloc.shuffle=1 spectre_v2=on spec_store_bypass_disable=on l1tf=full mds=full tsx=off tsx_async_abort=full retbleed=auto mitigations=auto vsyscall=none kvm.nx_huge_pages=force iommu=force intel_iommu=on amd_iommu=on efi=disable_early_pci_dma module.sig_enforce=1 lockdown=confidentiality quiet ipv6.disable=1 loglevel=0 apparmor=1 security=apparmor"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub

# SYSCTL
cat > /usr/lib/sysctl.d/sysctl.conf << 'EOF'
dev.tty.ldisc_autoload = 0
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 3
kernel.printk = 3 3 3 3
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.unprivileged_userns_clone = 1
kernel.yama.ptrace_scope = 2
kernel.modules_disabled = 1
net.core.bpf_jit_harden = 2
net.core.default_qdisc = fq
net.ipv4.conf.all.accept_local=0
net.ipv4.conf.default.accept_local=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.arp_evict_nocarrier=1
net.ipv4.conf.default.arp_evict_nocarrier=1
net.ipv4.conf.all.arp_filter=1
net.ipv4.conf.default.arp_filter=1
net.ipv4.conf.all.arp_ignore=2
net.ipv4.conf.default.arp_ignore=2
net.ipv4.conf.all.drop_gratuitous_arp=1
net.ipv4.conf.default.drop_gratuitous_arp=1
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.shared_media=0
net.ipv4.conf.all.forwarding=0
net.ipv4.conf.default.forwarding=0
net.ipv4.conf.all.mc.forwarding=0
net.ipv4.conf.default.mc.forwarding=0
net.ipv4.conf.all.route_localnet=0
net.ipv4.conf.default.route_localnet=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.shared_media=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.*.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_sack = 0
net.ipv4.tcp_syncookies = 1
user.max_user_namespaces = 0
vm.max_map_count = 262144
vm.mmap_min_addr = 65536
vm.unprivileged_userfaultfd = 0
EOF
sysctl --system

# MODULES
cat > /etc/modprobe.d/harden.conf << 'EOF'
blacklist nf_tables
install nf_tables /bin/false
blacklist nft_chain_nat
install nft_chain_nat /bin/false
blacklist ax25
install ax25 /bin/false
blacklist can
install can /bin/false
blacklist dccp
install dccp /bin/false
blacklist decnet
install decnet /bin/false
blacklist econet
install econet /bin/false
blacklist ipx
install ipx /bin/false
blacklist netrom
install netrom /bin/false
blacklist p8022
install p8022 /bin/false
blacklist p8023
install p8023 /bin/false
blacklist psnap
install psnap /bin/false
blacklist rds
install rds /bin/false
blacklist rose
install rose /bin/false
blacklist sctp
install sctp /bin/false
blacklist tipc
install tipc /bin/false
blacklist x25
install x25 /bin/false
blacklist atm
install atm /bin/false
blacklist kvm
install kvm /bin/false
blacklist kvm_intel
install kvm_intel /bin/false
blacklist kvm_amd
install kvm_amd /bin/false
blacklist vboxdrv
install vboxdrv /bin/false
blacklist vboxnetadp
install vboxnetadp /bin/false
blacklist vboxnetflt
install vboxnetflt /bin/false
blacklist vmmon
install vmmon /bin/false
blacklist vmw_vmci
install vmw_vmci /bin/false
blacklist xen
install xen /bin/false
blacklist cramfs
install cramfs /bin/false
blacklist freevxfs
install freevxfs /bin/false
blacklist jffs2
install jffs2 /bin/false
blacklist hfs
install hfs /bin/false
blacklist hfsplus
install hfsplus /bin/false
blacklist squashfs
install squashfs /bin/false
blacklist udf
install udf /bin/false
blacklist gfs2
install gfs2 /bin/false
blacklist floppy
install floppy /bin/false
blacklist firewire-core
install firewire-core /bin/false
blacklist usb_f_ecm
install usb_f_ecm /bin/false
blacklist usb_f_rndis
install usb_f_rndis /bin/false
blacklist nft_chain_nat
install nft_chain_nat /bin/false
blacklist nft_ct
install nft_ct /bin/false
blacklist nft_counter
install nft_counter /bin/false
blacklist nft_fib
install nft_fib /bin/false
blacklist nft_fib_inet
install nft_fib_inet /bin/false
blacklist nft_fib_ipv6
install nft_fib_ipv6 /bin/false
blacklist nft_fib_ipv4
install nft_fib_ipv4 /bin/false
blacklist nf_tables
install nf_tables /bin/false
blacklist nf_tables_set
install nf_tables_set /bin/false
blacklist nft_log
install nft_log /bin/false
blacklist nft_limit
install nft_limit /bin/false
blacklist nft_queue
install nft_queue /bin/false
blacklist nft_reject
install nft_reject /bin/false
blacklist mac80211
install mac80211 /bin/false
blacklist cfg80211
install cfg80211 /bin/false
blacklist iwlwifi
install iwlwifi /bin/false
blacklist ath*
install ath* /bin/false
blacklist brcmsmac
install brcmsmac /bin/false
blacklist brcmfmac
install brcmfmac /bin/false
blacklist rtl8*
install rtl8* /bin/false
blacklist rtl88*
install rtl88* /bin/false
blacklist rt2800*
install rt2800* /bin/false
blacklist mt76*
install mt76* /bin/false
blacklist bluetooth
install bluetooth /bin/false
blacklist btusb
install btusb /bin/false
blacklist btrtl
install btrtl /bin/false
blacklist btintel
install btintel /bin/false
blacklist btbcm
install btbcm /bin/false
blacklist usb_storage
install usb_storage /bin/false
blacklist uas
install uas /bin/false
blacklist lp
install lp /bin/false
blacklist ppdev
install ppdev /bin/false
blacklist parport
install parport /bin/false
blacklist hamradio
install hamradio /bin/false
blacklist af_802154
install af_802154 /bin/false
blacklist firewire-ohci
install firewire-ohci /bin/false
blacklist raw1394
install raw1394 /bin/false
blacklist jfs
install jfs /bin/false
blacklist reiserfs
install reiserfs /bin/false
blacklist dvb*
install dvb* /bin/false
blacklist r820t
install r820t /bin/false
blacklist rtl283*
install rtl283* /bin/false
blacklist rtl2830
install rtl2830 /bin/false
blacklist rtl2832
install rtl2832 /bin/false
blacklist rtl2838
install rtl2838 /bin/false
blacklist joydev
install joydev /bin/false
blacklist mousedev
install mousedev /bin/false
blacklist tap
install tap /bin/false
blacklist tun
install tun /bin/false
blacklist video1394
install video1394 /bin/false
blacklist garmin_gps
install garmin_gps /bin/false
blacklist gnss
install gnss /bin/false
blacklist gnss-serial
install gnss-serial /bin/false
blacklist gnss-usb
install gnss-usb /bin/false
EOF

# UNNECESSARY ACCOUNTS/GROUPS
groupdel _ssh --force
groupdel irc --force
groupdel kvm --force
groupdel voice --force
groupdel games --force
groupdel systemd-timesync --force
groupdel proxy --force
userdel www-data
userdel sync
userdel lp
userdel mail
userdel proxy
userdel dhcpcd
userdel games
userdel irc
userdel list
userdel news
userdel bluetooth
userdel uucp

# MOUNTS
echo "                                    
/dev/mapper/lvg-root                      /                          ext4       defaults,noatime,nodev,errors=remount-ro 0 1
/dev/mapper/lvg-home                      /home                      ext4       defaults,noatime,nodev,nosuid 0 2
/dev/mapper/lvg-run--shm                  /run/shm                   ext4       defaults,noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-tmp                       /tmp                       ext4       defaults,noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-usr                       /usr                       ext4       defaults,noatime,nodev,ro 0 2
/dev/mapper/lvg-var                       /var                       ext4       defaults,noatime,nodev,nosuid 0 2
/dev/mapper/lvg-var--log                  /var/log                   ext4       defaults,noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-var--log--audit           /var/log/audit             ext4       defaults,noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-var--tmp                  /var/tmp                   ext4       defaults,noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-swap                       none                      swap       sw 0 0
tmpfs                                     /home/user/.cache          tmpfs      defaults,noatime,nodev,nosuid,noexec,uid=1000,gid=1000,mode=700 0 0
proc                                      /proc                      proc       defaults,noatime,nodev,nosuid,noexec,hidepid=2 0 0
tmpfs                                     /run                       tmpfs      defaults,noatime,nodev,nosuid,noexec,mode=0755 0 0
tmpfs                                     /tmp                       tmpfs      defaults,noatime,nodev,nosuid,noexec,mode=1777 0 0
tmpfs                                     /var/tmp                   tmpfs      defaults,noatime,nodev,nosuid,noexec,bind,mode=1777
tmpfs                                     /dev/shm                   tmpfs      defaults,noatime,noexec,nosuid,mode=1777 0 0
udev                                      /dev                       devtmpfs   defaults,noatime,noexec,nosuid,noatime 0 0                              
devpts                                    /dev/pts                   devpts     defaults,noatime,noexec,nosuid,noatime,newinstance,ptmxmode=0666 0 0
" >> /etc/fstab

sed -i 's|^UUID=\([A-Za-z0-9-]\+\)[[:space:]]\+/boot/efi[[:space:]]\+vfat.*|UUID=\1                           /boot/efi                  vfat       noatime,nodev,nosuid,noexec,umask=0077 0 1|' /etc/fstab  

# PERMISSIONS
cd /etc
chown root:root cron.hourly cron.daily cron.weekly cron.monthly cron.d group group- passwd passwd- security iptables default sudoers fstab hosts.allow hosts.deny hosts host.conf
chmod 0644 /etc/passwd
chmod 0644 /etc/group
chmod 0640 /etc/shadow
chmod 0640 /etc/gshadow
chmod 0600 /etc/passwd-
chmod 0600 /etc/group-
chmod 0600 /etc/shadow-
chmod 0640 /etc/gshadow-
chmod 0640 /etc/fstab
chmod 0440 /etc/sudoers 
chmod 0600 /root/.bashrc
chmod 0600 /root/.profile
chmod 0600 /etc/security
chmod 0600 /etc/crontab
chown dev /home/dev
chmod 0700 /home/dev
chmod 0700 /root 
chmod 0700 /boot  
chown root:root /boot/grub/grub.cfg
chmod 0400 /boot/grub/grub.cfg
chmod -R 0400 /etc/iptables
chown root:root /var/run/dbus
chmod 0750 /var/run/dbus
chown root:root /run/systemd
chmod 0750 /run/systemd
chmod 0644 /etc/hosts.allow
chmod 0644 /etc/hosts.deny
chown root:root /etc/security/opasswd
chmod 0600 /etc/security/opasswd
chown root:adm -R /var/log
chmod -R 0640 /var/log
chmod 0400 /etc/crontab
chmod -R 0700 /etc/cron.hourly
chmod -R 0700 /etc/cron.daily
chmod -R 0700 /etc/cron.weekly
chmod -R 0700 /etc/cron.monthly
chmod -R 0700 /etc/cron.d
chmod -R 0400 /etc/cron.allow
chmod -R 0400 /etc/cron.deny
chmod -R 0400 /etc/at.allow
chmod -R 0700 /var/spool/cron
chmod -R 0700 /var/spool/at
cd

# LOCKDOWN
apt clean
apt autopurge 
apt purge "$(dpkg -l | grep '^rc' | awk '{print $2}')"
find / -perm -4000 -o -perm -2000 -exec chmod a-s {} \; 2>/dev/null
find / -perm -4000 -exec chmod u-s {} \;
find / -perm -4000 -exec chmod g-s {} \;
find / -perm -2000 -exec chmod u-s {} \;
find / -perm -2000 -exec chmod g-s {} \;
chmod u+s /usr/bin/sudo
chmod u+s /bin/sudo
chattr +i /etc/fstab
chattr +i /etc/adduser.conf
chattr +i /etc/group
chattr +i /etc/group-
chattr +i /etc/hosts
chattr +i /etc/host.conf
chattr +i /etc/hosts.allow
chattr +i /etc/hosts.deny
chattr +i /etc/login.defs
chattr +i /etc/default/grub
chattr +i /etc/passwd
chattr +i /etc/passwd-
chattr +i /etc/gshadow-
chattr +i /etc/gshadow
chattr -R +i /etc/sudoers*
chattr +i /root/.bashrc
chattr +i /etc/shadow
chattr +i /etc/shadow-
chattr +i /etc/shells
chattr -R +i /etc/pam.d
chattr +i /usr/lib/sysctl.d/sysctl.conf
chattr -R +i /etc/modprobe.d
chattr +i /etc/services
chattr +i /etc/sudoers
chattr -R +i /etc/security
chattr -R +i /etc/iptables
chattr -R +i /etc/ssh
chattr +i /etc/conf
chattr -R +i /etc/audit

# INTEGRITY CHECKING
echo "============================================"
echo "CONFIGURING ROOTKIT DETECTION"
echo "============================================"

# Configure rkhunter
sed -i 's/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf
sed -i 's/^MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf
sed -i 's/^WEB_CMD=.*/WEB_CMD=""/' /etc/rkhunter.conf
echo "ALLOWHIDDENDIR=/dev/.lxc" >> /etc/rkhunter.conf
echo "ALLOWHIDDENDIR=/dev/.udev" >> /etc/rkhunter.conf
echo "ALLOWHIDDENDIR=/dev/.static" >> /etc/rkhunter.conf
echo "ALLOWHIDDENDIR=/dev/.initramfs" >> /etc/rkhunter.conf

# Initialize rkhunter database
rkhunter --update 2>/dev/null || true
rkhunter --propupd

# Create debsums verification script
cat >/usr/local/bin/verify-system.sh <<'EOF'
#!/bin/bash
echo "Running system integrity checks..."
echo "=================================="
echo ""
echo "Checking package file integrity with debsums..."
debsums --changed --silent
echo ""
echo "Checking for rootkits with rkhunter..."
rkhunter --check --skip-keypress --report-warnings-only
echo ""
echo "Checking for rootkits with chkrootkit..."
chkrootkit -q
echo ""
echo "System integrity check complete."
EOF
chmod 755 /usr/local/bin/verify-system.sh

echo "Run 'sudo /usr/local/bin/verify-system.sh' to check system integrity"

# MULLVAD VPN
echo "============================================"
echo "MULLVAD VPN SETUP"
echo "============================================"
apt install -y git rsync curl wget dirmngr apt-transport-https ca-certificates lsb-release gnupg gpg
curl -fsSLo /usr/share/keyrings/mullvad-keyring.asc https://repository.mullvad.net/deb/mullvad-keyring.asc
echo "deb [signed-by=/usr/share/keyrings/mullvad-keyring.asc arch=$( dpkg --print-architecture )] https://repository.mullvad.net/deb/beta beta main" | tee /etc/apt/sources.list.d/mullvad.list
apt update
apt install -y mullvad-vpn mullvad-browser
echo ""
echo "IMPORTANT: You must configure Mullvad manually after installation:"
echo "1. Run: mullvad account login <YOUR_ACCOUNT_NUMBER>"
echo "2. Or complete the setup after the script finishes"
echo ""
echo "Pre-configuring Mullvad settings (will apply after login)..."
mullvad relay set tunnel wireguard --port 51820 2>/dev/null || true
mullvad relay set tunnel wireguard --ip-version ipv4 2>/dev/null || true
mullvad relay set tunnel-protocol wireguard 2>/dev/null || true
mullvad relay set location us nyc 2>/dev/null || true
mullvad tunnel set wireguard --daita on 2>/dev/null || true
mullvad obfuscation set mode off 2>/dev/null || true
mullvad auto-connect set on 2>/dev/null || true
echo "Mullvad pre-configured. Remember to login and connect manually!"

# VPN KILLSWITCH - Force all traffic through Mullvad
echo "============================================"
echo "CONFIGURING VPN KILLSWITCH"
echo "============================================"
iptables -F
iptables -X
iptables -Z
iptables -t nat -F
iptables -t nat -X
iptables -t nat -Z
iptables -t mangle -F
iptables -t mangle -X
iptables -t mangle -Z
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -i wg0-mullvad -j ACCEPT
iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT
iptables -A OUTPUT -o wg0-mullvad -j ACCEPT
iptables -A OUTPUT ! -o wg0-mullvad -m conntrack --ctstate NEW -j DROP
iptables -A INPUT -j DROP
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
iptables-save   > /etc/iptables/rules.v4
ip6tables-save  > /etc/iptables/rules.v6
netfilter-persistent save

# FINAL WARNINGS AND COMPLETION
echo ""
echo "============================================"
echo "HARDENING SCRIPT COMPLETED"
echo "============================================"
echo ""
echo "CRITICAL POST-INSTALLATION STEPS:"
echo "1. Login to Mullvad VPN:"
echo "   mullvad account login <YOUR_ACCOUNT_NUMBER>"
echo "   mullvad connect"
echo ""
echo "2. REBOOT THE SYSTEM to apply all changes"
echo ""
echo "3. After reboot, verify U2F login works BEFORE proceeding"
echo ""
echo "4. Test MAC randomization:"
echo "   ip link show eth0"
echo ""
echo "5. Verify VPN killswitch:"
echo "   curl https://am.i.mullvad.net/connected"
echo ""
echo "6. Run integrity check:"
echo "   sudo /usr/local/bin/verify-system.sh"
echo ""
echo "7. Review audit logs:"
echo "   sudo ausearch -m USER_LOGIN"
echo ""
echo "SECURITY NOTES:"
echo "- Root account is LOCKED (passwd -l root)"
echo "- All authentication requires U2F hardware key"
echo "- All network traffic MUST go through Mullvad VPN"
echo "- Compilers and debuggers are BLOCKED"
echo "- Most kernel modules are BLACKLISTED"
echo "- System files are IMMUTABLE (chattr +i)"
echo "- Automatic security updates are ENABLED"
echo ""
echo "To unlock immutable files: chattr -i <file>"
echo "To view audit logs: ausearch -k <key>"
echo "To check firewall: iptables -L -v -n"
echo ""
echo "============================================"
