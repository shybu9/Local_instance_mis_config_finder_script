import os
import re


service_names = ["apache2", "postgresql", "tor","nginx","tor","mysql"] 


suspicious_patterns = [

    r'Accepted publickey for',  # Successful SSH key authentication
    r'Failed password for',  # Failed password attempts
    r'uname=\w+ ',  # Suspicious user or group
    r'comm=\w+ ',   # Suspicious command or process name
    r'success=0 ',  # Unsuccessful events
    r'arch=c000003e syscall=',  # System calls
    r'file=.*config ',  # Access to configuration files
    r'exe=\S*[^/]*[^- ]$',  # Executable without a path
    r'Failed password for invalid user',
    r'Accepted publickey for',
    r' OR 1=1 --',
    r'UNION SELECT',
    r'SELECT * FROM',
    r'/admin'

    
]

def check_auth_logs(log_file):
    print(f"[+] checking logs under {log_file}")
    
    with open(log_file, 'r') as f:
        for line in f:
            for pattern in suspicious_patterns:
                if re.search(pattern, line):
                    print(f"[*] Suspicious activity found in {log_file}:\n\t{line}")


def search_logs_for_service(service_name):
    service_directory = os.path.join("/var/log", service_name)
    
    if not os.path.exists(service_directory):
        print(f"[-]Log directory for {service_name} does not exist.")
        return

    print("_"*15)
    print(f"[+]Checking logs for {service_name} service:")
    
    for root, _, files in os.walk(service_directory):
        for file in files:
            if file.endswith(".log"):
                log_file = os.path.join(root, file)
                with open(log_file, 'r') as f:
                    for line in f:
                        for pattern in suspicious_patterns:
                            #print(f"checking for {pattern} in {line} from {log_file}")
                            if re.search(pattern, line):
                                print(f"[*]Suspicious activity found in {log_file}:\n\t{line}")


    print(f"-"*15)
def main():
    auth_log_files = ['/var/log/auth.log', '/var/log/secure', '/var/log/audit/audit.log']

    for log_file in auth_log_files:
            try:
                check_auth_logs(log_file)
                #print(log_file)
            except FileNotFoundError:
                print(f"[-] File not found: {log_file}")
        
        

    for service_name in service_names:
        search_logs_for_service(service_name)

if __name__ == "__main__":
    main()
