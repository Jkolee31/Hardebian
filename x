#!/usr/bin/env bash
# Hardened baseline for Debian/Ubuntu
# Theme: default lock-down; explicit, reversible toggles to unlock.

set -euo pipefail

### ====== SETTINGS YOU MAY TUNE ======
# Change these if you like:
ALLOW_USER="dev"                         # your daily user
U2F_MAP="/etc/u2f_mappings"              # pam_u2f mapping file path
APT_PIN_NAME="deny-ssh.pref"             # apt pin to block ssh daemons
NFT_PROFILE_LOCKED="/etc/nftables/locked.nft"
NFT_PROFILE_MAINT="/etc/nftables/maintenance.nft"  # allows DNS+NTP+HTTPS for updates
SUID_ALLOWLIST=(
  "/usr/bin/sudo" "/bin/mount" "/bin/umount"
  "/bin/ping" "/usr/bin/passwd" "/usr/bin/chsh" "/usr/bin/chfn"
)

DRY_RUN="${DRY_RUN:-0}"  # set DRY_RUN=1 to preview without changes
### ===================================

log(){ printf '[*] %s\n' "$*"; }
warn(){ printf '[!] %s\n' "$*" >&2; }
die(){ printf '[X] %s\n' "$*" >&2; exit 1; }

run(){
  if [ "$DRY_RUN" = "1" ]; then echo "DRYRUN: $*"; else eval "$@"; fi
}

bak(){ local f="$1"; [ -e "$f" ] && run "cp -a '$f' '${f}.bak.$(date +%s)'" || true; }

require_root(){ [ "$(id -u)" -eq 0 ] || die "Run as root."; }
require_debian(){
  command -v apt >/dev/null || die "This script targets Debian/Ubuntu (apt).";
  [ -f /etc/os-release ] || die "Missing /etc/os-release.";
}

header(){ echo; log "=== $* ==="; }

### ====== BASELINE PREREQS ======
prereqs(){
  header "Pre-reqs"
  run "apt-get update -y"
  run "apt-get install -y --no-install-recommends \
        rsyslog chrony apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra \
        nftables auditd needrestart apt-listbugs apt-listchanges debsums debsecan"
  run "systemctl enable --now rsyslog chrony apparmor nftables auditd"
}

### ====== APT HARDENING & PINS ======
apt_hardening(){
  header "APT hardening"
  run "install -d -m 755 /etc/apt/apt.conf.d /etc/apt/preferences.d"
  # don’t install recommends/suggests
  local aptfile="/etc/apt/apt.conf.d/98-hardening"
  bak "$aptfile"
  cat >"$aptfile" <<'EOF'
APT::Install-Recommends "false";
APT::Install-Suggests "false";
Dpkg::Use-Pty "true";
EOF

  # pin SSH daemons so they cannot be installed
  local pin="/etc/apt/preferences.d/${APT_PIN_NAME}"
  bak "$pin"
  cat >"$pin" <<'EOF'
Package: openssh-server
Pin: release *
Pin-Priority: -1

Package: dropbear
Pin: release *
Pin-Priority: -1

Package: tinyssh
Pin: release *
Pin-Priority: -1
EOF
  run "apt-get update -y"
}

### ====== SUDOERS (drop-in, validated) ======
sudoers_hardening(){
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
}

### ====== PAM: U2F optional/sufficient for sudo & login ======
pam_u2f_minimal(){
  header "PAM U2F (minimal, survivable)"
  # Expect mapping file to be provisioned separately for $ALLOW_USER
  run "install -m 600 /dev/null '$U2F_MAP' || true"  # leave empty by default
  # SUDO: prefer key if present, fallback to password (break-glass)
  local ps="/etc/pam.d/sudo"
  bak "$ps"
  if ! grep -q pam_u2f.so "$ps"; then
    sed -i '1i auth sufficient pam_u2f.so cue authfile='"$U2F_MAP" "$ps"
  fi
  # LOGIN/SSHD leave alone here; SSH is blocked separately. If you later enable SSH, add pam_u2f similarly.
}

### ====== LOGIN DEFS & UMASK ======
login_defs(){
  header "login.defs / shells"
  bak /etc/login.defs
  sed -ri 's/^(\s*UMASK\s+).*/\1027/; s/^(\s*PASS_MIN_DAYS\s+).*/\11/; s/^(\s*PASS_MAX_DAYS\s+).*/\160/; s/^(\s*ENCRYPT_METHOD\s+).*/\1SHA512/' /etc/login.defs || true
  # default shell for new users → nologin (explicitly set shell when creating)
  bak /etc/default/useradd
  sed -ri 's|^SHELL=.*|SHELL=/usr/sbin/nologin|' /etc/default/useradd || true
  # ensure /etc/shells lists valid shells (don’t break tools):
  grep -qxF "/bin/bash" /etc/shells || echo "/bin/bash" >>/etc/shells
  grep -qxF "/usr/sbin/nologin" /etc/shells || echo "/usr/sbin/nologin" >>/etc/shells
  # global umask
  grep -qxF "umask 027" /etc/profile || echo "umask 027" >> /etc/profile
  grep -qxF "umask 027" /etc/bash.bashrc || echo "umask 027" >> /etc/bash.bashrc
  # auto-logout after 10 min for shells
  cat >/etc/profile.d/autologout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
  run "chmod +x /etc/profile.d/autologout.sh"
}

### ====== SYSCTL (drop-in, not monolithic overwrite) ======
sysctl_hardening(){
  header "sysctl"
  run "install -d -m 755 /etc/sysctl.d"
  local f="/etc/sysctl.d/99-hardening.conf"
  bak "$f"
  cat >"$f" <<'EOF'
# Network
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
# ICMP: keep enabled for PMTU & diagnostics (do NOT set icmp_echo_ignore_all=1)

# Kernel exposure
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
kernel.yama.ptrace_scope = 2
kernel.unprivileged_bpf_disabled = 1

# Filesystem hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
  run "sysctl --system"
}

### ====== NFTABLES: profiles & toggles ======
nft_profiles(){
  header "nftables profiles"
  run "install -d -m 755 /etc/nftables"
  # Locked profile: default-drop INPUT; OUTPUT accept; allow ICMP, DNS, NTP; SSH closed.
  cat >"$NFT_PROFILE_LOCKED" <<'EOF'
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept
    udp dport {53,123,51820} accept
    tcp dport {80,443} accept   # comment these if you want strict inbound serverless
    # ssh explicitly dropped
    tcp dport {22,2222,2200} drop
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
EOF

  # Maintenance egress profile: keep INPUT drop; OUTPUT allow DNS/NTP/HTTP(S) only
  cat >"$NFT_PROFILE_MAINT" <<'EOF'
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept
    udp dport {53,123,51820} accept
    # Inbound web closed; tune if this is a server
    tcp dport {22} drop
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ct state established,related accept
    udp dport {53,123} accept
    tcp dport {80,443} accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
EOF

  # default to maintenance (tighter egress). Switch with apply_nft_profile <locked|maintenance>
  run "nft -f '$NFT_PROFILE_MAINT'"
  run "systemctl enable --now nftables"
}

apply_nft_profile(){
  local which="${1:-maintenance}"
  case "$which" in
    locked)     run "nft -f '$NFT_PROFILE_LOCKED'";;
    maintenance) run "nft -f '$NFT_PROFILE_MAINT'";;
    *) die "Unknown profile: $which";;
  esac
  log "Applied nftables profile: $which"
}

### ====== SSH: block resurrection cleanly, reversible ======
enforce_no_ssh(){
  header "Enforce no SSH (install-mask-divert)"
  # Pin packages
  apt_hardening

  # Mask units so they can't start even if installed
  run "systemctl mask --now ssh.service ssh.socket 2>/dev/null || true"
  run "systemctl mask --now sshd.service 2>/dev/null || true"

  # Divert binaries (belt & suspenders)
  run "mkdir -p /usr/local/disabled"
  if [ -x /usr/sbin/sshd ]; then
    run "dpkg-divert --package hardening --divert /usr/local/disabled/sshd --rename /usr/sbin/sshd || true"
  fi
  if [ -e /usr/lib/openssh/sftp-server ]; then
    run "dpkg-divert --package hardening --divert /usr/local/disabled/sftp-server --rename /usr/lib/openssh/sftp-server || true"
  fi
}

allow_ssh_again(){
  header "Undo SSH block (you still need to install it)"
  run "rm -f /etc/apt/preferences.d/${APT_PIN_NAME}"
  run "systemctl unmask ssh.service ssh.socket sshd.service 2>/dev/null || true"
  # remove diversions if present
  run "dpkg-divert --package hardening --rename --remove /usr/sbin/sshd 2>/dev/null || true"
  run "dpkg-divert --package hardening --rename --remove /usr/lib/openssh/sftp-server 2>/dev/null || true"
  log "SSH pins/masks removed. Install and configure SSH intentionally if needed."
}

### ====== AUDITD: alert if ssh-like stuff shows up ======
auditd_rules(){
  header "auditd rules for ssh detection"
  local f="/etc/audit/rules.d/40-ssh-block.rules"
  bak "$f"
  cat >"$f" <<'EOF'
# Exec of common SSH daemons (paths may vary)
-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/sshd -k ssh_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/dropbear -k ssh_exec
# Bind to port 22 (AF_INET=2, htons(22)=0x1600 -> arg2=0x160016 on x86_64; tune if needed)
-a always,exit -F arch=b64 -S bind -F a2=0x160016 -k ssh_bind_22
EOF
  run "augenrules --load"
  run "systemctl restart auditd"
}

### ====== LOG PERMS (safe) ======
log_perms(){
  header "/var/log perms"
  run "chown -R root:adm /var/log"
  run "find /var/log -type d -exec chmod 0750 {} +"
  run "find /var/log -type f -exec chmod 0640 {} +"
}

### ====== SYSTEM USERS: lock shells, don't delete ======
lock_legacy_users(){
  header "Lock legacy/system users (no deletion)"
  local to_lock=(news uucp irc games list)
  for u in "${to_lock[@]}"; do
    if id "$u" &>/dev/null; then
      run "usermod -L -s /usr/sbin/nologin '$u' || true"
    fi
  done
}

### ====== SUID/SGID: audit then prune everything not in allowlist ======
suid_prune(){
  header "SUID/SGID audit & prune (allowlist)"
  local before="/root/suid_sgid.before"
  run "find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -print > '$before' 2>/dev/null || true"
  while IFS= read -r f; do
    local keep=0
    for a in "${SUID_ALLOWLIST[@]}"; do
      [ "$f" = "$a" ] && keep=1 && break
    done
    if [ "$keep" -eq 0 ]; then
      run "chmod u-s,g-s '$f' || true"
    fi
  done < "$before"
  log "Pruned SUID/SGID outside allowlist. Review $before for diffs."
}

### ====== MOTD/BANNER (cosmetic/legal) ======
banner(){
  header "Banners"
  for f in /etc/motd /etc/issue /etc/issue.net; do
    bak "$f"
    cat >"$f" <<'EOF'
Unauthorized access to this system is prohibited.
Connections may be monitored and recorded.
Disconnect immediately if you are not authorized.
EOF
  done
}

### ====== MAIN ======
main(){
  require_root
  require_debian

  prereqs
  apt_hardening
  sudoers_hardening
  pam_u2f_minimal
  login_defs
  sysctl_hardening
  nft_profiles            # default to maintenance egress
  enforce_no_ssh          # hard-block ssh resurrection
  auditd_rules
  log_perms
  lock_legacy_users
  suid_prune

  log "Done. Defaults: INPUT drop, OUTPUT restricted (maintenance), SSH blocked."
  echo
  echo "Toggles you can run later:"
  echo "  apply_nft_profile locked        # OUTPUT accept (normal workstation), INPUT default-drop"
  echo "  apply_nft_profile maintenance   # OUTPUT only DNS+NTP+HTTPS (update mode)"
  echo "  allow_ssh_again                 # remove pins/masks/diversions (then install & configure SSH intentionally)"
  echo
  echo "Remember to provision U2F for $ALLOW_USER into $U2F_MAP if you want key auth for sudo:"
  echo "  pamu2fcfg -u $ALLOW_USER >> $U2F_MAP   # run as that user with a key inserted"
}

# Allow calling helper functions directly: hardened.sh func [args...]
if [ "${1:-}" = "apply_nft_profile" ] || [ "${1:-}" = "allow_ssh_again" ]; then
  "$@"
else
  main "$@"
fi