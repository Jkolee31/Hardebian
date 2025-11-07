#!/usr/bin/env bash

set -euo pipefail

apt update

# PRE CONFIG/AUDIT
echo 'APT::Get::AllowUnauthenticated "false";' >> /etc/apt/apt.conf.d/98-hardening
echo 'APT::Install-Suggests "false";' >> /etc/apt/apt.conf.d/98-hardening 
echo 'APT::Install-Recommends "false";' >> /etc/apt/apt.conf.d/98-hardening
echo 'DPkg
  {
      Pre-Invoke  { "mount -o remount,rw /usr" };
      Pre-Invoke  { "mount -o remount,rw /boot" };
  };' >> /etc/apt/apt.conf.d/99-remount 

apt install -y git curl wget apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
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

systemctl disable debug-shell.service unattended-upgrades wpa_supplicant speech-dispatcher bluez bluetooth.service apport.service avahi-daemon.socket avahi-daemon.service cups-browsed cups.socket cups.path cups.service nvmf-autoconnect.service nvmefc-boot-connections.service pcscd.socket ModemManager.service systemd-pstore.service persist-autosave.service usbmuxd.service usb_modeswitch@.service usb-gadget.target mountnfs.service mountnfs-bootclean.service udisks2.service kexec.target systemd-kexec.service fprintd.service systemd-binfmt.service ctrl-alt-del.target rpcbind.target proc-sys-fs-binfmt_misc.mount proc-sys-fs-binfmt_misc.automount printer.target

systemctl mask debug-shell.service unattended-upgrades wpa_supplicant speech-dispatcher bluez bluetooth.service apport.service avahi-daemon.socket avahi-daemon.service cups-browsed cups.socket cups.path cups.service nvmf-autoconnect.service nvmefc-boot-connections.service pcscd.socket ModemManager.service systemd-pstore.service persist-autosave.service usbmuxd.service usb_modeswitch@.service usb-gadget.target mountnfs.service mountnfs-bootclean.service udisks2.service kexec.target systemd-kexec.service fprintd.service systemd-binfmt.service ctrl-alt-del.target rpcbind.target proc-sys-fs-binfmt_misc.mount proc-sys-fs-binfmt_misc.automount printer.target

apt purge -y  zram* pci* pmount* acpi* anacron* avahi* atmel* bc bind9* dns* fastfetch fonts-noto* fprint* isc-dhcp* lxc* docker* podman* xen* bochs* uml* vagrant* libssh* ssh* openssh* acpi* samba* winbind* qemu* libvirt* virt* cron* avahi* cup* print* rsync* virtual* sane* rpc* bind* nfs* blue* pp* spee* espeak* mobile* wireless* bc perl dictionaries-common doc-debian emacs* ethtool iamerican ibritish ienglish-common inet* ispell task-english util-linux-locales wamerican tasksel* vim* os-prober* netcat* libssh*


# FIREWALL (MULLVAD REQUIRED)
apt install iptables iptables-persistent netfilter-persistent
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
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i wg0-mullvad -j ACCEPT
iptables -A OUTPUT -o wg0-mullvad -j ACCEPT
iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT
iptables -A OUTPUT -j DROP
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
iptables-save > /etc/iptables/rules.v4
iptables-save > /etc/iptables/rules.v6
netfilter-persistent save

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

Package: vagrant*
Pin: release *
Pin-Priority: -1
EOF

# INSTALL PACKAGES
apt update 
apt install -y pamu2fcfg libpam-u2f rsyslog chrony libpam-tmpdir fail2ban needrestart aptitude apt-listchanges acct sysstat rkhunter chkrootkit clamav clamdscan clamav-freshclam debsums apt-show-versions tiger wget gnupg lsb-release apt-transport-https unzip patch pulseaudio pulseaudio-utils pavucontrol alsa-utils lynis macchanger unhide tcpd haveged auditd fonts-liberation extrepo timeshift gnome-terminal gnome-brave-icon-theme breeze-gtk-theme bibata* tcpd macchanger mousepad xfce4 libxfce4ui-utils thunar xfce4-panel xfce4-session xfce4-settings xfce4-terminal xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulse* xfce4-whisk* lightdm lightdm-gtk-greeter lightdm-gtk-greeter-settings opensnitch* python3-opensnitch*

# PAM/U2F
pamu2fcfg -u dev > /etc/u2f_mappings
chmod 600 /etc/u2f_mappings
chown root:root /etc/u2f_mappings
chattr +i /etc/u2f_mappings

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
account   required    pam_access.so
account   required    pam_unix.so
EOF

cat >/etc/pam.d/common-password <<'EOF'
#%PAM-1.0
password  [success=1  default=ignore]  pam_unix.so obscure use_authtok try_first_pass yescrypt
password  requisite   pam_deny.so
EOF

cat >/etc/pam.d/common-auth <<'EOF'
#%PAM-1.0
auth      sufficient  pam_u2f.so authfile=/etc/u2f_mappings
auth      requisite   pam_deny.so
EOF

cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session	  required    pam_env.so
session	  optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   required    pam_unix.so
EOF

cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session	  required    pam_env.so
session	  optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   required    pam_unix.so
EOF

cat >/etc/pam.d/sudo <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/u2f_mappings
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/sudo-i <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/u2f_mappings
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/sshd <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/u2f_mappings
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/su <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/u2f_mappings
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/su-l <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/u2f_mappings
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
auth      required    pam_u2f.so authfile=/etc/u2f_mappings
account   include     common-account
session   include     common-session
password  include     common-password
EOF

cat >/etc/pam.d/lightdm <<'EOF'
#%PAM-1.0
auth      requisite   pam_nologin.so
auth      required    pam_u2f.so authfile=/etc/u2f_mappings
account   include     common-account
session   [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close
session   include     common-session
session   [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open
password  include     common-password
EOF

cat >/etc/pam.d/lightdm-greeter <<'EOF'
#%PAM-1.0
auth      requisite    pam_nologin
password  required     pam_unix.so
session   optional     pam_systemd.so
session   include      common-session
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

cat >/etc/sudoers <<'EOF'
Defaults passwd_tries=2
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
root   ALL=(ALL) ALL
%sudo  ALL=(ALL) ALL
EOF

# MISC HARDENING 
echo "/bin/bash" > /etc/shells
passwd -l root
echo "needs_root_rights=no" >> /etc/X11/Xwrapper.config
dpkg-reconfigure xserver-xorg-legacy
echo "order hosts" >> /etc/host.conf
echo "*            -          maxlogins    1
      root         -          maxlogins    5
      *            soft       priority     0
      *            hard       nproc        2048
      root         hard       nproc        65536
      *            soft       core         0
      *            hard       core         unlimited" > /etc/security/limits.conf.d/55-limits.conf
echo "ProcessSizeMax=0
Storage=none" >> /etc/systemd/coredump.conf
echo "ulimit -c 0" >> /etc/profile
echo "UMASK 077" >> /etc/login.defs
echo "umask 077" >> /etc/profile
echo "umask 077" >> /etc/bash.bashrc
echo "ALL: ALL" > /etc/hosts.deny
echo "-:ALL EXCEPT dev:tty1" > /etc/security/access.conf
echo "-:ALL EXCEPT dev:LOCAL" >> /etc/security/access.conf
echo "-:dev:ALL EXCEPT LOCAL" >> /etc/security/access.conf
echo "+:dev:tty1" >> /etc/security/access.conf
echo "-:root:ALL" >> /etc/security/access.conf
echo "-:ALL:ALL" >> /etc/security/access.conf

 # GRUB
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge slab_debug=FZ init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on vsyscall=none pti=on debugfs=off kfence.sample_interval=100 efi_pstore.pstore_disable=1 amd_iommu=force_isolation intel_iommu=on iommu=force iommu.passthrough=0 efi=disable_early_pci_dma random.trust_bootloader=off random.trust_cpu=off extra_latent_entropy iommu.strict=1 vdso32=0 page_alloc.shuffle=1 mitigations=auto,nosmt nosmt=force spectre_v2=on spectre_bhi=on spec_store_bypass_disable=on ssbd=force-on l1tf=full,force kvm-intel.vmentry_l1d_flush=always mds=full,nosmt tsx=off lockdown=confidentiality tsx_async_abort=full,nosmt kvm.nx_huge_pages=force l1d_flush=on mmio_stale_data=full,nosmt retbleed=auto,nosmt module.sig_enforce=1 kvm.mitigate_smt_rsb=1 gather_data_sampling=force spec_rstack_overflow=safe-ret reg_file_data_sampling=on ipv6.disable=1 loglevel=0 quiet audit=1 apparmor=1 security=apparmor audit=1"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub 

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
install kvm /bin/false
blacklist kvm_intel
install kvm_intel /bin/false
blacklist kvm_amd
install kvm_amd /bin/false
blacklist vboxdrv
install vboxdrv /bin/false
blacklist vboxnetflt
install vboxnetflt /bin/false
blacklist vboxnetadp
install vboxnetadp /bin/false
blacklist vmw_vmci
install vmw_vmci /bin/false
blacklist vmmon
install vmmon /bin/false
blacklist xen
install xen /bin/false
blacklist af_802154
install af_802154 /bin/false
blacklist amdgpu
install amdgpu /bin/false
blacklist appletalk
install appletalk /bin/false	
blacklist ath9k
install ath9k /bin/false
blacklist atm
install atm /bin/false
blacklist asus_acpi
install asus_acpi /bin/false	
blacklist ax25
install ax25 /bin/false
blacklist b43
install b43 /bin/false
blacklist bcm43xx
install bcm43xx /bin/false
blacklist bluetooth
install bluetooth /bin/false
blacklist btusb
install btusb /bin/false
blacklist can
install can /bin/false
blacklist cdrom
install cdrom /bin/false
blacklist cifs
install cifs /bin/false
blacklist cramfs
install cramfs /bin/false
blacklist dccp
install dccp /bin/false
blacklist decnet
install decnet /bin/false
blacklist de4x5
install de4x5 /bin/false
blacklist dvb_core
install dvb_core /bin/false
blacklist dvb_usb_rtl2832u
install dvb_usb_rtl2832u /bin/false
blacklist dvb_usb_rtl28xxu
install dvb_usb_rtl28xxu /bin/false
blacklist dvb_usb_v2
install dvb_usb_v2 /bin/false
blacklist econet
install econet /bin/false
blacklist eepro100
install eepro100 /bin/false
blacklist eth1394
install eth1394 /bin/false
blacklist exfat
install exfat /bin/false
blacklist fddi
install fddi /bin/false
blacklist firewire
install firewire /bin/false
blacklist firewire-core
install firewire-core /bin/false
blacklist firewire_core
install firewire_core /bin/false
blacklist firewire-ohci
install firewire-ohci /bin/false
blacklist firewire_ohci
install firewire_ohci /bin/false
blacklist firewire-sbp2
install firewire-sbp2 /bin/false
blacklist firewire_sbp2
install firewire_sbp2 /bin/false
blacklist floppy
install floppy /bin/false
blacklist freevxfs
install freevxfs /bin/false
blacklist garmin_gps
install garmin_gps /bin/false
blacklist gfs2
install gfs2 /bin/false
blacklist gnss
install gnss /bin/false
blacklist gnss-mtk
install gnss-mtk /bin/false
blacklist gnss-serial
install gnss-serial /bin/false
blacklist gnss-sirf
install gnss-sirf /bin/false
blacklist gnss-usb
install gnss-usb /bin/false
blacklist gnss-ubx
install gnss-ubx /bin/false
blacklist hamradio
install hamradio /bin/false
blacklist hfs
install hfs /bin/false
blacklist hfsplus
install hfsplus /bin/false
blacklist ib_ipoib
install ib_ipoib /bin/false
blacklist ipx
install ipx /bin/false
blacklist jffs2
install jffs2 /bin/false	
blacklist jfs
install jfs /bin/false
blacklist joydev
install joydev /bin/false
blacklist ksmbd
install ksmbd /bin/false
blacklist lp
install lp /bin/false
blacklist msr
install msr /bin/false
blacklist n-hdlc
install n-hdlc /bin/false
blacklist netrom
install netrom /bin/false
blacklist nfs
install nfs /bin/false
blacklist nfsv3
install nfsv3 /bin/false
blacklist nfsv4
install nfsv4 /bin/false
blacklist ntfs
install ntfs /bin/false
blacklist nvidia
install nvidia /bin/false
blacklist ohci1394
install ohci1394 /bin/false
blacklist p8022
install p8022 /bin/false
blacklist p8023
install p8023 /bin/false	
blacklist parport
install parport /bin/false
blacklist pmt_class
install pmt_class /bin/false	
blacklist pmt_telemetry
install pmt_telemetry /bin/false	
blacklist ppp_async
install ppp_async /bin/false	
blacklist ppp_deflate
install ppp_deflate /bin/false
blacklist ppp_generic
install ppp_generic /bin/false
blacklist pppoe
install pppoe /bin/false	
blacklist pppox
install pppox /bin/false	
blacklist prism54
install prism54 /bin/false
blacklist psnap
install psnap /bin/false	
blacklist r820t
install r820t /bin/false	
blacklist radeon
install radeon /bin/false		
blacklist raw1394
install raw1394 /bin/false
blacklist rds
install rds /bin/false
blacklist reiserfs
install reiserfs /bin/false
blacklist rose
install rose /bin/false
blacklist rtl2830
install rtl2830 /bin/false
blacklist rtl2832
install rtl2832 /bin/false
blacklist rtl2832_sdr
install rtl2832_sdr /bin/false
blacklist rtl2838
install rtl2838 /bin/false
blacklist rtl8187
install rtl8187 /bin/false
blacklist sbp2
install sbp2 /bin/false
blacklist sctp
install sctp /bin/false
blacklist slhc
install slhc /bin/false
blacklist squashfs
install squashfs /bin/false
blacklist sr_mod
install sr_mod /bin/false
blacklist tipc
install tipc /bin/false
blacklist tr
install tr /bin/false
blacklist udf
install udf /bin/false
blacklist usb_storage
install usb_storage /bin/false
blacklist uvcvideo
install uvcvideo /bin/false
blacklist uinput
install uinput /bin/false
blacklist video1394
install video1394 /bin/false
blacklist vivid
install vivid /bin/false
blacklist x25
install x25 /bin/false
EOF

# KERNEL
rm -r /etc/sysctl.d
echo "dev.tty.ldisc_autoload=0
dev.tty.legacy_tiocsti=0
fs.protected_fifos=2
fs.protected_hardlinks=1
fs.protected_regular=2
fs.protected_symlinks=1
fs.suid_dumpable=0
kernel.core_uses_pid=1
kernel.dmesg_restrict=1
kernel.kexec_load_disabled=1
kernel.kptr_restrict=2
kernel.perf_event_paranoid=3
kernel.core_pattern=|/bin/true
kernel.printk=3 3 3 3
kernel.randomize_va_space=2
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
kernel.unprivileged_userns_clone=1
kernel.yama.ptrace_scope=3
net.core.bpf_jit_harden=2
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_forward=0
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_orphan_retries=2
net.ipv4.tcp_retries=5
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_syn_retries=5
net.ipv4.tcp_syncookies=1
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
net.ipv6.conf.default.disable_ipv6=1
vm.swappiness=1" > /usr/lib/sysctl.d/sysctl.conf
sysctl --system

# MOUNTS
echo "
udev                                       /dev             devtmpfs    defaults,noatime,noexec,nosuid 0 0
devpts                                   /dev/pts             devpts    defaults,nosuid,noexec,newinstance,ptmxmode=0666 0 0
proc                                       /proc              proc      defaults,nosuid,noexec,nodev,hidepid=2 0 0
tmpfs                                /home/dev/.cache         tmpfs     defaults,nosuid,noexec,nodev,uid=1000,gid=1000,mode=0700 0 0
tmpfs       				                        /run              tmpfs   	defaults,nodev,nosuid,noexec,mode=0755 0 0
tmpfs      				                        /dev/shm            tmpfs   	defaults,nodev,nosuid,noexec,mode=1777 0 0
tmpfs       				                        /tmp              tmpfs   	defaults,nodev,nosuid,noexec,mode=1777 0 0
tmpfs       				                      /var/tmp   	        tmpfs   	defaults,nodev,nosuid,noexec,mode=1777 0 0
" >> /etc/fstab

# PERMISSIONS
cd /etc
sudo chown root:root cron.hourly cron.daily cron.weekly cron.monthly cron.d group group- passwd passwd- security iptables default sudoers fstab hosts.allow hosts.deny hosts host.conf
sudo chmod 0644 /etc/passwd
sudo chmod 0644 /etc/group
sudo chmod 0640 /etc/shadow
sudo chmod 0640 /etc/gshadow
sudo chmod 0600 /etc/passwd-
sudo chmod 0600 /etc/group-
sudo chmod 0600 /etc/shadow-
sudo chmod 0640 /etc/gshadow-
sudo chmod 0640 /etc/sysctl.conf
sudo chmod 0640 /etc/logrotate.conf
sudo chmod 0640 /etc/fstab
sudo chmod 0440 /etc/sudoers 
sudo chmod 0600 /root/.bashrc
sudo chmod 0600 /root/.profile
sudo chmod 0600 /etc/security
sudo chmod 0600 /etc/crontab
sudo chown dev /home/dev
sudo chmod 0700 /home/dev
sudo chmod 0700 /root 
sudo chmod 0700 /boot  
sudo chown root:root /boot/grub/grub.cfg
sudo chmod 0400 /boot/grub/grub.cfg
sudo chmod 0400 /etc/iptables
sudo chown root:root /var/run/dbus
sudo chmod 0750 /var/run/dbus
sudo chown root:root /run/sshd
sudo chmod 0750 /run/sshd
sudo chown root:root /run/systemd
sudo chmod 0750 /run/systemd
sudo chmod 0644 /etc/hosts.allow
sudo chmod 0644 /etc/hosts.deny
sudo chown root:root /etc/security/opasswd
sudo chmod 0600 /etc/security/opasswd
sudo chown root:adm -R /var/log/
sudo chmod -R 640 /var/log/
sudo chmod 0600 /var/log/faillog
sudo chown root:root /etc/ssh/sshd_config
sudo chmod 0400 /etc/ssh/sshd_config
sudo chown root:root /etc/ssh/ssh_config
sudo chmod 0400 /etc/ssh/ssh_config
sudo chmod -f 0700 /etc/cron.monthly/*
sudo chmod -f 0700 /etc/cron.weekly/*
sudo chmod -f 0700 /etc/cron.daily/*
sudo chmod -f 0700 /etc/cron.hourly/*
sudo chmod -f 0700 /etc/cron.d/*
sudo chmod -f 0400 /etc/cron.allow
sudo chmod -f 0400 /etc/cron.deny
sudo chmod -f 0400 /etc/crontab
sudo chmod -f 0400 /etc/at.allow
sudo chmod -f 0400 /etc/at.deny
sudo chmod -f 0700 /etc/cron.daily
sudo chmod -f 0700 /etc/cron.weekly
sudo chmod -f 0700 /etc/cron.monthly
sudo chmod -f 0700 /etc/cron.hourly
sudo chmod -f 0700 /var/spool/cron
sudo chmod -f 0600 /var/spool/cron/*
sudo chmod -f 0700 /var/spool/at
sudo chmod -f 0600 /var/spool/at/*
cd

# LOCKDOWN
find / -perm -4000 -o -perm -2000 -exec sudo chmod a-s {} \; 2>/dev/null
find / -perm -4000 -exec sudo chmod u-s {} \;
find / -perm -4000 -exec sudo chmod g-s {} \;
find / -perm -2000 -exec sudo chmod u-s {} \;
find / -perm -2000 -exec sudo chmod g-s {} \;
sudo chmod u+s /usr/bin/sudo
sudo chmod u+s /bin/sudo
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
chattr -R +i /etc/security
chattr -R +i /etc/ssh

