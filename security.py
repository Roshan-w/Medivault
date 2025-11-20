"""
MediVault Security Module
Implements Snowflake ID generation, file hashing, encryption, and deduplication
"""

import hashlib
import time
import threading
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

# SNOWFLAKE ID GENERATOR 
class SnowflakeIDGenerator:
    """
    Twitter Snowflake ID Generator
    64-bit ID structure:
    - 1 bit: unused (always 0)
    - 41 bits: timestamp in milliseconds
    - 10 bits: machine/datacenter ID
    - 12 bits: sequence number
    """
    
    def __init__(self, datacenter_id=1, worker_id=1):
        self.datacenter_id = datacenter_id & 0x1F  
        self.worker_id = worker_id & 0x1F  
        self.sequence = 0
        self.last_timestamp = -1
        self.lock = threading.Lock()
        
        # Custom epoch (January 1, 2024)
        self.epoch = int(datetime(2024, 1, 1).timestamp() * 1000)
        
    def _current_millis(self):
        return int(time.time() * 1000)
    
    def _wait_next_millis(self, last_timestamp):
        timestamp = self._current_millis()
        while timestamp <= last_timestamp:
            timestamp = self._current_millis()
        return timestamp
    
    def generate_id(self):
        with self.lock:
            timestamp = self._current_millis()
            
            if timestamp < self.last_timestamp:
                raise Exception("Clock moved backwards!")
            
            if timestamp == self.last_timestamp:
                self.sequence = (self.sequence + 1) & 0xFFF  # 12 bits
                if self.sequence == 0:
                    timestamp = self._wait_next_millis(self.last_timestamp)
            else:
                self.sequence = 0
            
            self.last_timestamp = timestamp
            
            # Build the ID
            snowflake_id = (
                ((timestamp - self.epoch) << 22) |
                (self.datacenter_id << 17) |
                (self.worker_id << 12) |
                self.sequence
            )
            
            return snowflake_id
    
    def generate_string_id(self):
        """Generate a base62 encoded string ID for URLs"""
        snowflake_id = self.generate_id()
        return self._base62_encode(snowflake_id)
    
    def _base62_encode(self, num):
        """Encode number to base62 for shorter URLs"""
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        if num == 0:
            return alphabet[0]
        
        result = []
        base = len(alphabet)
        while num:
            num, rem = divmod(num, base)
            result.append(alphabet[rem])
        return ''.join(reversed(result))
    
    def decode_id(self, snowflake_id):
        """Decode a Snowflake ID to get timestamp, datacenter, worker, and sequence"""
        timestamp = ((snowflake_id >> 22) + self.epoch)
        datacenter_id = (snowflake_id >> 17) & 0x1F
        worker_id = (snowflake_id >> 12) & 0x1F
        sequence = snowflake_id & 0xFFF
        
        return {
            'timestamp': datetime.fromtimestamp(timestamp / 1000),
            'datacenter_id': datacenter_id,
            'worker_id': worker_id,
            'sequence': sequence
        }


# ==================== FILE SECURITY ====================
class FileHasher:
    """
    File hashing and deduplication system
    Supports MD5, SHA-256, and SHA-512
    """
    
    @staticmethod
    def calculate_hash(file_path, algorithm='sha256'):
        """Calculate file hash using specified algorithm"""
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        if algorithm not in hash_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hasher = hash_algorithms[algorithm]
        
        try:
            with open(file_path, 'rb') as f:
                # Read in chunks for memory efficiency
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            raise Exception(f"Error calculating hash: {str(e)}")
    
    @staticmethod
    def calculate_file_hash_from_bytes(file_bytes, algorithm='sha256'):
        """Calculate hash from file bytes (for Flask file uploads)"""
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        if algorithm not in hash_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hasher = hash_algorithms[algorithm]
        hasher.update(file_bytes)
        return hasher.hexdigest()
    
    @staticmethod
    def verify_file_integrity(file_path, expected_hash, algorithm='sha256'):
        """Verify file hasn't been tampered with"""
        current_hash = FileHasher.calculate_hash(file_path, algorithm)
        return current_hash == expected_hash
    
    @staticmethod
    def generate_file_metadata(file_path):
        """Generate comprehensive file metadata"""
        return {
            'md5': FileHasher.calculate_hash(file_path, 'md5'),
            'sha256': FileHasher.calculate_hash(file_path, 'sha256'),
            'sha512': FileHasher.calculate_hash(file_path, 'sha512'),
            'size': os.path.getsize(file_path),
            'created': datetime.fromtimestamp(os.path.getctime(file_path)),
            'modified': datetime.fromtimestamp(os.path.getmtime(file_path))
        }


# ==================== FILE ENCRYPTION ====================
class FileEncryption:
    """
    File encryption/decryption using Fernet (AES-128)
    """
    
    def __init__(self, master_key=None):
        """Initialize with master key or generate new one"""
        if master_key:
            self.key = master_key.encode() if isinstance(master_key, str) else master_key
        else:
            self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def get_key(self):
        """Get the encryption key (store this securely!)"""
        return self.key.decode()
    
    def encrypt_file(self, input_path, output_path=None):
        """Encrypt a file"""
        try:
            with open(input_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = self.cipher.encrypt(file_data)
            
            output_path = output_path or f"{input_path}.encrypted"
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            return output_path
        except Exception as e:
            raise Exception(f"Encryption error: {str(e)}")
    
    def decrypt_file(self, input_path, output_path=None):
        """Decrypt a file"""
        try:
            with open(input_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.cipher.decrypt(encrypted_data)
            
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
                return output_path
            else:
                return decrypted_data
        except Exception as e:
            raise Exception(f"Decryption error: {str(e)}")
    
    def encrypt_bytes(self, data):
        """Encrypt bytes data"""
        return self.cipher.encrypt(data)
    
    def decrypt_bytes(self, encrypted_data):
        """Decrypt bytes data"""
        return self.cipher.decrypt(encrypted_data)
    
    @staticmethod
    def generate_key_from_password(password, salt=None):
        """Generate encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt


# ==================== DEDUPLICATION MANAGER ====================
class DeduplicationManager:
    """
    Manages file deduplication using content hashing
    """
    
    def __init__(self, medical_record_class):
        """
        Initialize with MedicalRecord class instead of db.session
        """
        self.MedicalRecord = medical_record_class
    
    def check_duplicate(self, file_hash, patient_id=None):
        """
        Check if file already exists
        Returns: (is_duplicate, existing_records)
        """
        query = self.MedicalRecord.query.filter_by(file_hash=file_hash)
        
        if patient_id:
            # Check for duplicates for this specific patient
            patient_records = query.filter_by(patient_id=patient_id).all()
            all_records = query.all()
            
            return {
                'is_duplicate': len(patient_records) > 0,
                'patient_duplicates': patient_records,
                'all_duplicates': all_records,
                'count': len(all_records)
            }
        else:
            records = query.all()
            return {
                'is_duplicate': len(records) > 0,
                'duplicates': records,
                'count': len(records)
            }
    
    def find_similar_files(self, file_path, threshold=0.95):
        """
        Find files with similar content (for near-duplicate detection)
        This is a simplified version - in production, use perceptual hashing
        """
        # Placeholder for advanced similarity detection
        # Could implement: perceptual hashing, fuzzy hashing, etc.
        pass


# ==================== AUDIT LOGGER ====================
class SecurityAuditLogger:
    """
    Enhanced security audit logging
    """
    
    @staticmethod
    def log_file_operation(operation, file_info, user_info, ip_address, status='success'):
        """Log file-related security operations"""
        log_entry = {
            'timestamp': datetime.utcnow(),
            'operation': operation,
            'file_hash': file_info.get('hash'),
            'file_name': file_info.get('name'),
            'file_size': file_info.get('size'),
            'user_id': user_info.get('id'),
            'user_name': user_info.get('name'),
            'user_type': user_info.get('type'),
            'ip_address': ip_address,
            'status': status
        }
        # In production, write to secure audit log database
        return log_entry
    
    @staticmethod
    def log_security_event(event_type, description, severity='info', metadata=None):
        """Log security-related events"""
        log_entry = {
            'timestamp': datetime.utcnow(),
            'event_type': event_type,
            'description': description,
            'severity': severity,
            'metadata': metadata or {}
        }
        # In production, write to SIEM or security log system
        return log_entry


# ==================== INITIALIZE GLOBAL INSTANCES ====================
# Singleton instances
snowflake_generator = SnowflakeIDGenerator(datacenter_id=1, worker_id=1)
file_hasher = FileHasher()

# Generate or load encryption key (In production, load from secure key management system)
ENCRYPTION_KEY = os.environ.get('MEDIVAULT_ENCRYPTION_KEY') or Fernet.generate_key()
file_encryptor = FileEncryption(ENCRYPTION_KEY)


# ==================== HELPER FUNCTIONS ====================
def generate_patient_id():
    """Generate unique patient ID using Snowflake"""
    return snowflake_generator.generate_id()

def generate_secure_id():
    """Generate URL-safe secure ID"""
    return snowflake_generator.generate_string_id()

def hash_file(file_path):
    """Calculate SHA-256 hash of file"""
    return file_hasher.calculate_hash(file_path, 'sha256')

def hash_file_bytes(file_bytes):
    """Calculate SHA-256 hash of file bytes"""
    return file_hasher.calculate_file_hash_from_bytes(file_bytes, 'sha256')

def encrypt_medical_file(file_path):
    """Encrypt a medical file"""
    return file_encryptor.encrypt_file(file_path)

def decrypt_medical_file(encrypted_path):
    """Decrypt a medical file"""
    return file_encryptor.decrypt_file(encrypted_path)


if __name__ == '__main__':
    # Test the security module
    print("=== MediVault Security Module Test ===\n")
    
    # Test Snowflake ID generation
    print("1. Snowflake ID Generation:")
    for i in range(5):
        snowflake_id = snowflake_generator.generate_id()
        string_id = snowflake_generator.generate_string_id()
        decoded = snowflake_generator.decode_id(snowflake_id)
        print(f"   ID {i+1}: {snowflake_id} | String: {string_id}")
        print(f"   Decoded: {decoded}")
    
    print("\n2. File Hashing:")
    print(f"   Test string hash (SHA-256): {hashlib.sha256(b'Hello MediVault').hexdigest()}")
    
    print("\n3. Encryption Key:")
    print(f"   Generated Key: {file_encryptor.get_key()[:50]}...")
    
    print("\n=== Security Module Ready ===")