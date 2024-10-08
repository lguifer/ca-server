import configparser

class Config:
    def __init__(self, ca_cert_path, ca_key_path, ca_directory, server_directory, validity_days, crl_path, IP, port, use_tls, web_key_path, web_cert_path):
        # CA and certificate settings
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.ca_directory = ca_directory
        self.server_directory = server_directory
        self.validity_days = validity_days
        self.crl_path = crl_path
        # Web server settings
        self.IP = IP
        self.port = port
        self.use_tls = use_tls
        self.web_key_path = web_key_path
        self.web_cert_path = web_cert_path

    def print_config(self):
        config_vars = {
            "CA Certificate Path": self.ca_cert_path,
            "CA Key Path": self.ca_key_path,
            "CA Directory": self.ca_directory,
            "Server Directory": self.server_directory,
            "Validity Days": self.validity_days,
            "CRL Path": self.crl_path,
            "IP": self.IP,
            "port": self.port,
            "Use TLS": self.use_tls,
            "Web Key Path": self.web_key_path,
            "Web Cert Path": self.web_cert_path,
        }
        for key, value in config_vars.items():
            print(f"{key}: {value}")

def preprocess_config_file(config_file):
    """
    Preprocess the config file to remove comments and strip trailing spaces.
    If no comment is present, the line remains unchanged.
    """
    with open(config_file, 'r') as f:
        lines = f.readlines()

    processed_lines = []
    for line in lines:
        # Remove everything after a '#' (if it exists)
        if '#' in line:
            line = line.split('#', 1)[0]
        # Strip any leading/trailing whitespace
        line = line.strip()
        if line:  # Only add non-empty lines
            processed_lines.append(line + '\n')
    
    return processed_lines

def load_config(config_file):
    # Preprocess the config file
    processed_lines = preprocess_config_file(config_file)
    
    # Create a temporary file in-memory to hold the preprocessed configuration
    config = configparser.ConfigParser()
    config.read_string(''.join(processed_lines))

    # Create and return a Config object
    return Config(
        ca_cert_path=config['directories']['ca_cert_path'].strip(),
        ca_key_path=config['directories']['ca_key_path'].strip(),
        ca_directory=config['directories']['ca_directory'].strip(),
        server_directory=config['directories']['server_directory'].strip(),
        validity_days=int(config['cert']['validity_days'].strip()),
        crl_path=config['directories']['crl_path'].strip(),
        IP=config['webserver']['IP'].strip(),
        port = config['webserver']['port'].strip(),
        use_tls=config['webserver']['use_tls'].strip().lower(),
        web_key_path=config['webserver']['web_key_path'].strip(),
        web_cert_path=config['webserver']['web_cert_path'].strip(),
    )




