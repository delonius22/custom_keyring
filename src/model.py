import os
import yaml
import base64
import logging
from getpass import getpass
from typing import Dict, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CustomEncryptedKeyring:
    """
    A custom keyring backend that uses YAML for data storage and encryption for security.
    """

    def __init__(self, filename: str = 'custom_keyring.yaml'):
        self.filename: str = filename
        self.key: Optional[bytes] = None
        self.data: Dict[str, Dict[str, str]] = {}

    def _derive_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def _load_data(self) -> None:
        if not os.path.exists(self.filename):
            logging.info(f"Keyring file {self.filename} not found. Creating a new one.")
            self._save_data()
            return

        try:
            with open(self.filename, 'r') as file:
                encrypted_data: Dict[str, str] = yaml.safe_load(file)

            if not encrypted_data:
                logging.warning(f"Keyring file {self.filename} is empty. Initializing with empty data.")
                self._save_data()
                return

            if self.key is None:
                password = getpass("Enter the master password to unlock the keyring: ")
                self.key, _ = self._derive_key(password, base64.b64decode(encrypted_data['salt']))

            f = Fernet(self.key)
            decrypted_data = f.decrypt(encrypted_data['data'].encode())
            self.data = yaml.safe_load(decrypted_data)
        except Exception as e:
            logging.error(f"Error loading keyring data: {str(e)}")
            self.data = {}

    def _save_data(self) -> None:
        try:
            if self.key is None:
                password = getpass("Set a master password for the keyring: ")
                self.key, salt = self._derive_key(password)
            else:
                _, salt = self._derive_key(Fernet(self.key).extract_timestamp().to_bytes(8, 'big').decode())

            f = Fernet(self.key)
            encrypted_data = f.encrypt(yaml.dump(self.data).encode())
            
            data_to_save: Dict[str, str] = {
                'salt': base64.b64encode(salt).decode(),
                'data': encrypted_data.decode()
            }

            with open(self.filename, 'w') as file:
                yaml.dump(data_to_save, file)
            
            logging.info(f"Keyring data saved to {self.filename}")
        except Exception as e:
            logging.error(f"Error saving keyring data: {str(e)}")

    def set_password(self, service: str, username: str, password: str) -> None:
        self._load_data()
        if service not in self.data:
            self.data[service] = {}
        self.data[service][username] = password
        self._save_data()
        logging.info(f"Password set for {username} in {service}")

    def get_password(self, service: str, username: str) -> Optional[str]:
        self._load_data()
        password = self.data.get(service, {}).get(username)
        if password:
            logging.info(f"Password retrieved for {username} in {service}")
        else:
            logging.info(f"No password found for {username} in {service}")
        return password

    def delete_password(self, service: str, username: str) -> None:
        self._load_data()
        if service in self.data and username in self.data[service]:
            del self.data[service][username]
            if not self.data[service]:
                del self.data[service]
            self._save_data()
            logging.info(f"Password deleted for {username} in {service}")
        else:
            logging.info(f"No password found to delete for {username} in {service}")

def main() -> None:
    keyring = CustomEncryptedKeyring()

    # Set a password
    keyring.set_password('MyService', 'MyUsername', 'MySecurePassword')

    # Get the password
    retrieved_password: Optional[str] = keyring.get_password('MyService', 'MyUsername')
    print(f"Retrieved password: {retrieved_password}")

    # Delete the password
    keyring.delete_password('MyService', 'MyUsername')

    # Try to retrieve the deleted password
    deleted_password: Optional[str] = keyring.get_password('MyService', 'MyUsername')
    print(f"Deleted password (should be None): {deleted_password}")

if __name__ == "__main__":
    main()

