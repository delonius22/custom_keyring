import os
import json
import base64
import logging
from getpass import getpass
from typing import Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecureKeyring:
    def __init__(self, filename: str = 'secure_keyring.json'):
        self.filename: str = filename
        self.master_key: Optional[bytes] = None
        self.fernet: Optional[Fernet] = None
        self.data: Dict[str, str] = {}

    def _derive_key(self, password: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
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

    def _initialize_fernet(self, master_password: str) -> None:
        salt = self._load_salt()
        if salt is None:
            self.master_key, salt = self._derive_key(master_password)
            self._save_salt(salt)
        else:
            self.master_key, _ = self._derive_key(master_password, salt)
        self.fernet = Fernet(self.master_key)

    def _load_salt(self) -> Optional[bytes]:
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as file:
                data = json.load(file)
                return base64.b64decode(data.get('salt', ''))
        return None

    def _save_salt(self, salt: bytes) -> None:
        data = {'salt': base64.b64encode(salt).decode(), 'data': {}}
        with open(self.filename, 'w') as file:
            json.dump(data, file)

    def _load_data(self) -> None:
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as file:
                data = json.load(file)
                encrypted_data = data.get('data', {})
                for key, value in encrypted_data.items():
                    try:
                        decrypted_value = self.fernet.decrypt(value.encode()).decode()
                        self.data[key] = decrypted_value
                    except Exception as e:
                        logging.error(f"Error decrypting data for {key}: {str(e)}")

    def _save_data(self) -> None:
        encrypted_data = {}
        for key, value in self.data.items():
            encrypted_value = self.fernet.encrypt(value.encode()).decode()
            encrypted_data[key] = encrypted_value
        
        with open(self.filename, 'r+') as file:
            data = json.load(file)
            data['data'] = encrypted_data
            file.seek(0)
            json.dump(data, file)
            file.truncate()

    def set_password(self, service: str, username: str, password: str) -> None:
        if self.fernet is None:
            master_password = getpass("Enter the master password: ")
            self._initialize_fernet(master_password)
        
        self._load_data()
        self.data[f"{service}:{username}"] = password
        self._save_data()
        logging.info(f"Password set for {username} in {service}")

    def get_password(self, service: str, username: str) -> Optional[str]:
        if self.fernet is None:
            master_password = getpass("Enter the master password: ")
            self._initialize_fernet(master_password)
        
        self._load_data()
        password = self.data.get(f"{service}:{username}")
        if password:
            logging.info(f"Password retrieved for {username} in {service}")
            return password
        else:
            logging.info(f"No password found for {username} in {service}")
            return None

    def delete_password(self, service: str, username: str) -> None:
        if self.fernet is None:
            master_password = getpass("Enter the master password: ")
            self._initialize_fernet(master_password)
        
        self._load_data()
        key = f"{service}:{username}"
        if key in self.data:
            del self.data[key]
            self._save_data()
            logging.info(f"Password deleted for {username} in {service}")
        else:
            logging.info(f"No password found to delete for {username} in {service}")

def main():
    keyring = SecureKeyring()

    # Set passwords
    keyring.set_password('MyService', 'MyUsername', 'MySecurePassword')
    keyring.set_password('AnotherService', 'AnotherUser', 'AnotherPassword')

    # Get the passwords
    retrieved_password1 = keyring.get_password('MyService', 'MyUsername')
    print(f"Retrieved password for MyService: {retrieved_password1}")

    retrieved_password2 = keyring.get_password('AnotherService', 'AnotherUser')
    print(f"Retrieved password for AnotherService: {retrieved_password2}")

    # Delete a password
    keyring.delete_password('MyService', 'MyUsername')

    # Try to retrieve the deleted password
    deleted_password = keyring.get_password('MyService', 'MyUsername')
    print(f"Deleted password (should be None): {deleted_password}")

    # The other password should still be there
    still_there = keyring.get_password('AnotherService', 'AnotherUser')
    print(f"Password that should still be there: {still_there}")

if __name__ == "__main__":
    main()