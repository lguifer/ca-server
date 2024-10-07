import configparser

class Config:
    def __init__(self, ca_cert_path, ca_key_path, ca_directory, server_directory, validity_days, crl_path):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.ca_directory = ca_directory
        self.server_directory = server_directory
        self.validity_days = validity_days
        self.crl_path = crl_path

    def print_config(self):
        config_vars = {
            "CA Certificate Path": self.ca_cert_path,
            "CA Key Path": self.ca_key_path,
            "CA Directory": self.ca_directory,
            "Server Directory": self.server_directory,
            "Validity Days": self.validity_days,
            "CRL Path": self.crl_path
        }
        for key, value in config_vars.items():
            print(f"{key}: {value}")

def load_config(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)

    # Create and return a Config object
    return Config(
        ca_cert_path=config['directories']['ca_cert_path'].strip(),
        ca_key_path=config['directories']['ca_key_path'].strip(),
        ca_directory=config['directories']['ca_directory'].strip(),
        server_directory=config['directories']['server_directory'].strip(),
        validity_days=int(config['cert']['validity_days'].strip()),
        crl_path=config['directories']['crl_path'].strip()
    )


