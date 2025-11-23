from botocore.config import Config as S3Config
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from functools import wraps
from pathlib import Path
from typing import Tuple
import boto3
import hashlib
import logging
import os

load_dotenv()

MAX_FILE_SIZE_MB = 200

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE_MB * 1024 * 1024  # 100MB max upload

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Backend configuration."""
    S3_BUCKET = os.getenv('S3_BUCKET')
    S3_KEY_PREFIX = os.getenv('S3_KEY_PREFIX', 'database-backups')
    BACKEND_API_TOKEN = os.getenv('BACKEND_API_TOKEN')
    TEMP_UPLOAD_DIR = Path(os.getenv('TEMP_UPLOAD_DIR', '/tmp/db-uploads'))
    RETENTION_DAYS = int(os.getenv('RETENTION_DAYS', '30'))
    MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024 #B
    
    def __init__(self):
        if not self.S3_BUCKET:
            raise ValueError("S3_BUCKET environment variable not set")
        if not self.BACKEND_API_TOKEN:
            raise ValueError("BACKEND_API_TOKEN environment variable not set")
        
        self.TEMP_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


config = Config()

# ============================================================================
# S3 OPERATIONS
# ============================================================================

class S3Manager:
    """Handles S3 operations using IAM role credentials."""
    
    def __init__(self):
        """S3 client uses IAM role — no keys needed."""
        s3_config = S3Config(
            max_pool_connections=5,
            retries={'max_attempts': 3, 'mode': 'adaptive'},
            signature_version='s3v4',
        )
        
        self.client = boto3.client('s3', config=s3_config)
    
    def upload_file(self, filepath: Path, file_hash: str) -> Tuple[bool, str]:
        """Upload file to S3 with metadata."""
        try:
            if not filepath.exists() or filepath.stat().st_size == 0:
                return False, "File not found or empty"
            
            if filepath.stat().st_size > config.MAX_FILE_SIZE:
                return False, f"File exceeds max size of {config.MAX_FILE_SIZE / (1024*1024)}MB"
            
            s3_key = self._generate_s3_key(filepath.name)
            
            metadata = {
                'uploaded-at': datetime.now().isoformat(),
                'file-hash': file_hash,
                'original-filename': filepath.name,
            }
            
            self.client.upload_file(
                str(filepath),
                config.S3_BUCKET,
                s3_key,
                ExtraArgs={
                    'ServerSideEncryption': 'AES256',
                    'Metadata': metadata,
                    'ContentType': 'application/x-sqlite3'
                }
            )
            
            logger.info(f"Uploaded to S3: s3://{config.S3_BUCKET}/{s3_key}")
            return True, s3_key
            
        except ClientError as e:
            logger.error(f"S3 error: {e}")
            return False, str(e)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return False, str(e)
    
    def cleanup_old_backups(self) -> int:
        """Remove backups older than retention period."""
        try:
            cutoff_date = datetime.now() - timedelta(days=config.RETENTION_DAYS)
            
            response = self.client.list_objects_v2(
                Bucket=config.S3_BUCKET,
                Prefix=config.S3_KEY_PREFIX
            )
            
            if 'Contents' not in response:
                return 0
            
            deleted_count = 0
            for obj in response['Contents']:
                if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                    self.client.delete_object(
                        Bucket=config.S3_BUCKET,
                        Key=obj['Key']
                    )
                    deleted_count += 1
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old backups from S3")
            
            return deleted_count
            
        except ClientError as e:
            logger.error(f"Cleanup error: {e}")
            return 0
    
    def _generate_s3_key(self, filename: str) -> str:
        """Generate S3 key with timestamp."""
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        return f"{config.S3_KEY_PREFIX}/{timestamp}_{filename}"


# ============================================================================
# AUTHENTICATION
# ============================================================================

def require_token(f):
    """Decorator to verify API token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token or token != config.BACKEND_API_TOKEN:
            logger.warning(f"Unauthorized request from {request.remote_addr}")
            return jsonify({'error': 'Unauthorized'}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function


# ============================================================================
# ROUTES
# ============================================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy'}), 200


@app.route('/api/database/backup', methods=['POST'])
@require_token
def upload_backup():
    """
    Receive database backup from client and upload to S3.
    
    Request:
        - file: SQLite database file
        - file_hash: SHA256 hash for integrity verification
    """
    try:
        # Validate request
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        claimed_hash = request.form.get('file_hash', '')
        if not claimed_hash:
            return jsonify({'error': 'Missing file_hash'}), 400
        
        # Validate file type (should be .db)
        if not file.filename.endswith('.db'):
            return jsonify({'error': 'Invalid file type'}), 400
        
        # Save temporarily
        temp_path = config.TEMP_UPLOAD_DIR / file.filename
        file.save(str(temp_path))
        
        # Verify file hash (integrity check)
        actual_hash = _calculate_hash(temp_path)
        if actual_hash != claimed_hash:
            temp_path.unlink()
            logger.error(f"Hash mismatch for {file.filename}")
            return jsonify({'error': 'File integrity check failed'}), 400
        
        # Upload to S3
        s3_manager = S3Manager()
        success, result = s3_manager.upload_file(temp_path, actual_hash)
        
        if not success:
            temp_path.unlink()
            return jsonify({'error': result}), 500
        
        # Cleanup old backups
        s3_manager.cleanup_old_backups()
        
        # Delete temporary file
        temp_path.unlink()
        
        logger.info(f"Backup uploaded successfully: {result}")
        return jsonify({
            'status': 'success',
            's3_key': result,
            'file_hash': actual_hash
        }), 200
        
    except Exception as e:
        logger.error(f"Backup upload error: {e}")
        try:
            temp_path.unlink()
        except Exception as e:
            pass
        return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# UTILITIES
# ============================================================================

def _calculate_hash(filepath: Path) -> str:
    """Calculate SHA256 hash of file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({'error': 'File too large'}), 413


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404
