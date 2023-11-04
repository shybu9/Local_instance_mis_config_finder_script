import re

# Define the path to the SSH configuration file
ssh_config_path = '/etc/ssh/sshd_config'


# config_options_list = ['PermitRootLogin', 'PasswordAuthentication', '']


def ssh_policy_check():
    common_keys = ssh_desired_config.keys() & ssh_config.keys()

    # Output the common key-value pairs
    for key in common_keys:
        value1 = ssh_desired_config[key]
        value2 = ssh_config[key]
        if value2 == value1:
            finely_configured[key] = value1
        if value2 != value1:
            intentionally_misconfig[key] = value2

    uncomman_keys = [key for key in ssh_desired_config if key not in ssh_config]
    for key in uncomman_keys:
        defualt_potential_misconfig.append(key)


finely_configured = {}
defualt_potential_misconfig = []
intentionally_misconfig = {}
ssh_config = {}
ssh_desired_config = {
    "PermitRootLogin": "no",
    "PasswordAuthentication": "no",
    "DenyUsers": "root",
    "DenyGroups": 'root',
    "Port": 2222,
    "AllowTcpForwarding": "no",
    "PermitEmptyPasswords": "no",
    "PubkeyAuthentication": "yes",
    "UsePAM": "yes",
    "MaxAuthTries": 3,
    "MaxSessions": 10,
    "ClientAliveInterval": 300,
    "ClientAliveCountMax": 0,
    "TCPKeepAlive": "yes",
    "Banner": "/etc/ssh/banner"
}
ssh_potential_misconfig = {
    "AllowGroups": ['root', 'sudoers', 'wheel', 'admin'],
    "AllowUsers": "root"
}

# Read the SSH configuration file
with open(ssh_config_path, 'r') as config_file:
    for line in config_file:
        # Skip comments and empty lines
        if re.match(r'^\s*#', line) or not line.strip():
            continue

        # Extract configuration options and values
        match = re.match(r'^\s*([A-Za-z_]\w*)\s+(.+)$', line)
        if match:
            option, value = match.groups()
            ssh_config[option] = value


ssh_policy_check()
if finely_configured:
    print("_" * 15)
    print("| FINELY CONFIGURED |")
    print("-" * 15)
    for key_value in finely_configured:
        print(f"[+] {key_value}: {finely_configured[key_value]}")
    print("-" * 15)

if defualt_potential_misconfig:
    print("_" * 20)
    print("| POTENTIAL DEFUALT MISCONFIGURED |")
    print("-" * 20)
    for element in defualt_potential_misconfig:
        print(f"[-] {element}")
    print("-" * 20)

if intentionally_misconfig:
    print("_" * 30)
    print("| INTENTIONALLY MISCONFIGURED HEADERS: |")
    print("-" * 30)
    for key_value in intentionally_misconfig:
        print(f"[+] {key_value}: {intentionally_misconfig[key_value]}")
    print("-"*30)
