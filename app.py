#app.py
from flask import Flask, request, jsonify, redirect
import os
import subprocess
import logging
import hmac
import hashlib
import shutil
import json
import asyncio
from github import Github, GithubIntegration
from dotenv import load_dotenv
from datetime import datetime
from flask_cors import CORS
from models import db, AnalysisResult
from sqlalchemy import or_, text
import traceback
import requests
from urllib.parse import urlencode
from asgiref.wsgi import WsgiToAsgi
from scanner import SecurityScanner, ScanConfig, scan_repository_handler
from api import api, analysis_bp
from gitlab_api import gitlab_api
import ssl

if os.getenv('FLASK_ENV') != 'production':
    load_dotenv()

app = Flask(__name__)
CORS(app)
asgi_app = WsgiToAsgi(app)
app.register_blueprint(api)
app.register_blueprint(analysis_bp)
app.register_blueprint(gitlab_api)

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

logging.basicConfig(
    level=logging.INFO if os.getenv('FLASK_ENV') == 'production' else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database Configuration
# Database Configuration
DATABASE_URL = os.getenv('DATABASE_URL')
GITLAB_DATABASE_URL = os.getenv('GITLAB_DATABASE_URL')

if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

if GITLAB_DATABASE_URL and GITLAB_DATABASE_URL.startswith('postgres://'):
    GITLAB_DATABASE_URL = GITLAB_DATABASE_URL.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_BINDS'] = {
    'gitlab': GITLAB_DATABASE_URL
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Updated SSL configuration
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {
        'sslmode': 'require'
    }
}

# For GitLab database specifically
app.config['SQLALCHEMY_BIND_OPTIONS'] = {
    'gitlab': {
        'connect_args': {
            'sslmode': 'require'
        }
    }
}

# Initialize database
try:
    db.init_app(app)
    logger.info("Database initialization successful")
    
    with app.app_context():
        # Create tables in both databases
        db.create_all()  # For GitHub database
        
        # For GitLab database
        if GITLAB_DATABASE_URL:
            gitlab_engine = db.get_engine(app, bind='gitlab')
            db.Model.metadata.create_all(bind=gitlab_engine)
        
        # Test connections
        db.session.execute(text('SELECT 1'))
        if GITLAB_DATABASE_URL:
            db.session.execute(text('SELECT 1').execution_options(bind='gitlab'))
        db.session.commit()
        logger.info("Database connections successful")
        
        # Check and add columns
        try:
            # Check for user_id column
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='analysis_results' AND column_name='user_id'
            """))
            column_exists = bool(result.scalar())
            
            if not column_exists:
                logger.info("Adding user_id column...")
                db.session.execute(text("""
                    ALTER TABLE analysis_results 
                    ADD COLUMN IF NOT EXISTS user_id VARCHAR(255)
                """))
                db.session.execute(text("""
                    CREATE INDEX IF NOT EXISTS ix_analysis_results_user_id 
                    ON analysis_results (user_id)
                """))
                db.session.commit()
                logger.info("user_id column added successfully")
            else:
                logger.info("user_id column already exists")

            # Check for rerank column
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='analysis_results' AND column_name='rerank'
            """))
            rerank_exists = bool(result.scalar())
            
            if not rerank_exists:
                logger.info("Adding rerank column...")
                db.session.execute(text("""
                    ALTER TABLE analysis_results 
                    ADD COLUMN IF NOT EXISTS rerank JSONB
                """))
                db.session.commit()
                logger.info("rerank column added successfully")
            else:
                logger.info("rerank column already exists")

        except Exception as column_error:
            logger.error(f"Error managing columns: {str(column_error)}")
            db.session.rollback()
            raise

except Exception as e:
    logger.error(f"Database initialization error: {str(e)}")
    logger.error(traceback.format_exc())
    raise
@app.cli.command("create-gitlab-db")
def create_gitlab_db():
    """Create GitLab database tables."""
    with app.app_context():
        gitlab_engine = db.get_engine(app, bind='gitlab')
        db.Model.metadata.create_all(bind=gitlab_engine)

@app.cli.command("drop-gitlab-db")
def drop_gitlab_db():
    """Drop GitLab database tables."""
    with app.app_context():
        gitlab_engine = db.get_engine(app, bind='gitlab')
        db.Model.metadata.drop_all(bind=gitlab_engine)

def format_private_key(key_data):
    """Format the private key correctly for GitHub integration"""
    try:
        if not key_data:
            raise ValueError("Private key is empty")
        
        key_data = key_data.strip()
        
        if '\\n' in key_data:
            parts = key_data.split('\\n')
            key_data = '\n'.join(part.strip() for part in parts if part.strip())
        elif '\n' not in key_data:
            key_length = len(key_data)
            if key_length < 64:
                raise ValueError("Key content too short")
            
            if not key_data.startswith('-----BEGIN'):
                key_data = (
                    '-----BEGIN RSA PRIVATE KEY-----\n' +
                    '\n'.join(key_data[i:i+64] for i in range(0, len(key_data), 64)) +
                    '\n-----END RSA PRIVATE KEY-----'
                )
        
        if not key_data.startswith('-----BEGIN RSA PRIVATE KEY-----'):
            key_data = '-----BEGIN RSA PRIVATE KEY-----\n' + key_data
        if not key_data.endswith('-----END RSA PRIVATE KEY-----'):
            key_data = key_data + '\n-----END RSA PRIVATE KEY-----'
        
        lines = key_data.split('\n')
        if len(lines) < 3:
            raise ValueError("Invalid key format - too few lines")
        
        logger.info("Private key formatted successfully")
        return key_data
        
    except Exception as e:
        logger.error(f"Error formatting private key: {str(e)}")
        raise ValueError(f"Private key formatting failed: {str(e)}")

def verify_webhook_signature(request_data, signature_header):
    """Enhanced webhook signature verification for GitHub webhooks"""
    try:
        webhook_secret = os.getenv('GITHUB_WEBHOOK_SECRET')
        
        logger.info("Starting webhook signature verification")
        
        if not webhook_secret:
            logger.error("GITHUB_WEBHOOK_SECRET environment variable is not set")
            return False

        if not signature_header:
            logger.error("No X-Hub-Signature-256 header received")
            return False

        if not signature_header.startswith('sha256='):
            logger.error("Signature header doesn't start with sha256=")
            return False
            
        received_signature = signature_header.replace('sha256=', '')
        
        if isinstance(webhook_secret, str):
            webhook_secret = webhook_secret.strip().encode('utf-8')
            
        if isinstance(request_data, str):
            request_data = request_data.encode('utf-8')
            
        mac = hmac.new(
            webhook_secret,
            msg=request_data,
            digestmod=hashlib.sha256
        )
        expected_signature = mac.hexdigest()
        
        logger.debug("Signature Details:")
        logger.debug(f"Request Data Length: {len(request_data)} bytes")
        logger.debug(f"Secret Key Length: {len(webhook_secret)} bytes")
        logger.debug(f"Raw Request Data: {request_data[:100]}...")
        logger.debug(f"Received Header: {signature_header}")
        logger.debug(f"Calculated HMAC: sha256={expected_signature}")
        
        is_valid = hmac.compare_digest(expected_signature, received_signature)
        
        if not is_valid:
            logger.error("Signature mismatch detected")
            logger.error(f"Header format: {signature_header}")
            logger.error(f"Received signature: {received_signature[:10]}...")
            logger.error(f"Expected signature: {expected_signature[:10]}...")
            
            if os.getenv('FLASK_ENV') != 'production':
                logger.debug(f"Full received: {received_signature}")
                logger.debug(f"Full expected: {expected_signature}")
        else:
            logger.info("Webhook signature verified successfully")
            
        return is_valid

    except Exception as e:
        logger.error(f"Signature verification failed: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def verify_gitlab_webhook_signature(request_data, signature_header):
    """Verify GitLab webhook signature"""
    try:
        webhook_secret = os.getenv('GITLAB_WEBHOOK_SECRET')
        if not webhook_secret or not signature_header:
            return False

        expected_signature = hmac.new(
            webhook_secret.encode('utf-8'),
            msg=request_data,
            digestmod=hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature_header, expected_signature)
    except Exception as e:
        logger.error(f"GitLab signature verification failed: {str(e)}")
        return False

@app.route('/api/v1/gitlab/webhook', methods=['POST'])
def gitlab_webhook():
    """Handle GitLab webhook events"""
    try:
        signature = request.headers.get('X-Gitlab-Token')
        if not verify_gitlab_webhook_signature(request.get_data(), signature):
            return jsonify({'error': 'Invalid signature'}), 401

        event_type = request.headers.get('X-Gitlab-Event')
        event_data = request.get_json()

        if event_type == 'Push Hook':
            project_id = event_data.get('project', {}).get('id')
            project_url = event_data.get('project', {}).get('web_url')
            user_id = event_data.get('user_id')

            if not all([project_id, project_url, user_id]):
                return jsonify({'error': 'Missing required information'}), 400

            asyncio.run(scan_gitlab_repository_handler(
                project_url=project_url,
                access_token=os.getenv('GITLAB_TOKEN'),
                user_id=str(user_id)
            ))

        return jsonify({'success': True})

    except Exception as e:
        logger.error(f"GitLab webhook error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/gitlab/oauth/callback')
def gitlab_oauth_callback():
    """Handle GitLab OAuth callback"""
    try:
        code = request.args.get('code')
        if not code:
            return jsonify({'error': 'No code provided'}), 400

        # Exchange code for access token
        data = {
            'client_id': GITLAB_APP_ID,
            'client_secret': GITLAB_APP_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': GITLAB_CALLBACK_URL
        }

        response = requests.post('https://gitlab.com/oauth/token', data=data)
        if response.status_code == 200:
            token_data = response.json()
            # Get user information
            headers = {'Authorization': f"Bearer {token_data['access_token']}"}
            user_response = requests.get('https://gitlab.com/api/v4/user', headers=headers)
            
            if user_response.status_code == 200:
                user_data = user_response.json()
                frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
                params = urlencode({
                    'status': 'success',
                    'user_id': str(user_data['id']),
                    'platform': 'gitlab',
                    'access_token': token_data['access_token']
                })
                return redirect(f"{frontend_url}/auth/callback?{params}")
            
            return jsonify({'error': 'Failed to get user information'}), 400
        
        return jsonify({'error': 'Failed to get access token'}), 400

    except Exception as e:
        logger.error(f"GitLab OAuth error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/debug/test-webhook', methods=['POST'])
def test_webhook():
    """Test endpoint to verify webhook signatures"""
    if os.getenv('FLASK_ENV') != 'production':
        try:
            webhook_secret = os.getenv('GITHUB_WEBHOOK_SECRET')
            raw_data = request.get_data()
            received_signature = request.headers.get('X-Hub-Signature-256')
            
            result = verify_webhook_signature(raw_data, received_signature)
            
            mac = hmac.new(
                webhook_secret.encode('utf-8') if isinstance(webhook_secret, str) else webhook_secret,
                msg=raw_data,
                digestmod=hashlib.sha256
            )
            expected_signature = f"sha256={mac.hexdigest()}"
            
            return jsonify({
                'webhook_secret_configured': bool(webhook_secret),
                'webhook_secret_length': len(webhook_secret) if webhook_secret else 0,
                'received_signature': received_signature,
                'expected_signature': expected_signature,
                'payload_size': len(raw_data),
                'signatures_match': result,
                'raw_data_preview': raw_data.decode('utf-8')[:100] if raw_data else None
            })
        except Exception as e:
            return jsonify({'error': str(e)})
    return jsonify({'message': 'Not available in production'}), 403


def clean_directory(directory):
    """Safely remove a directory"""
    try:
        if os.path.exists(directory):
            shutil.rmtree(directory)
    except Exception as e:
        logger.error(f"Error cleaning directory {directory}: {str(e)}")

def trigger_semgrep_analysis(repo_url, installation_token, user_id):
    """Run Semgrep analysis with enhanced error handling"""
    clone_dir = None
    repo_name = repo_url.split('github.com/')[-1].replace('.git', '')
    
    try:
        repo_url_with_auth = f"https://x-access-token:{installation_token}@github.com/{repo_name}.git"
        clone_dir = f"/tmp/semgrep_{repo_name.replace('/', '_')}_{os.getpid()}"
        
        # Create initial database entry
        analysis = AnalysisResult(
            repository_name=repo_name,
            user_id=user_id,
            status='in_progress'
        )
        db.session.add(analysis)
        db.session.commit()
        logger.info(f"Created analysis record with ID: {analysis.id}")
        
        # Clean directory first
        clean_directory(clone_dir)
        logger.info(f"Cloning repository to {clone_dir}")
        
        # Enhanced clone command with detailed error capture
        try:
            # First verify the repository exists and is accessible
            test_url = f"https://api.github.com/repos/{repo_name}"
            headers = {
                'Authorization': f'Bearer {installation_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            logger.info(f"Verifying repository access: {test_url}")
            
            response = requests.get(test_url, headers=headers)
            if response.status_code != 200:
                raise ValueError(f"Repository verification failed: {response.status_code} - {response.text}")
            
            # Clone with more detailed error output
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url_with_auth, clone_dir],
                capture_output=True,
                text=True
            )
            
            if clone_result.returncode != 0:
                error_msg = (
                    f"Git clone failed with return code {clone_result.returncode}\n"
                    f"STDERR: {clone_result.stderr}\n"
                    f"STDOUT: {clone_result.stdout}"
                )
                logger.error(error_msg)
                raise Exception(error_msg)
                
            logger.info(f"Repository cloned successfully: {repo_name}")
            
            # Run semgrep analysis
            semgrep_cmd = ["semgrep", "--config=auto", "--json", "."]
            logger.info(f"Running semgrep with command: {' '.join(semgrep_cmd)}")
            
            semgrep_process = subprocess.run(
                semgrep_cmd,
                capture_output=True,
                text=True,
                check=True,
                cwd=clone_dir
            )
            
            try:
                semgrep_output = json.loads(semgrep_process.stdout)
                analysis.status = 'completed'
                analysis.results = semgrep_output
                db.session.commit()
                
                logger.info(f"Semgrep analysis completed successfully for {repo_name}")
                return semgrep_process.stdout
                
            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse Semgrep output: {str(e)}"
                logger.error(error_msg)
                analysis.status = 'failed'
                analysis.error = error_msg
                db.session.commit()
                return None

        except subprocess.CalledProcessError as e:
            error_msg = (
                f"Command '{' '.join(e.cmd)}' failed with return code {e.returncode}\n"
                f"STDERR: {e.stderr}\n"
                f"STDOUT: {e.stdout}"
            )
            logger.error(error_msg)
            if 'analysis' in locals():
                analysis.status = 'failed'
                analysis.error = error_msg
                db.session.commit()
            raise Exception(error_msg)

    except Exception as e:
        logger.error(f"Analysis error for {repo_name}: {str(e)}")
        if 'analysis' in locals():
            analysis.status = 'failed'
            analysis.error = str(e)
            db.session.commit()
        return None
        
    finally:
        if clone_dir:
            clean_directory(clone_dir)

def format_semgrep_results(raw_results):
    """Format Semgrep results for frontend"""
    try:
        # Handle string input
        if isinstance(raw_results, str):
            try:
                results = json.loads(raw_results)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON results: {str(e)}")
                return {
                    'summary': {
                        'total_files_scanned': 0,
                        'total_findings': 0,
                        'files_scanned': [],
                        'semgrep_version': 'unknown',
                        'scan_status': 'failed'
                    },
                    'findings': [],
                    'findings_by_severity': {
                        'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
                    },
                    'findings_by_category': {},
                    'errors': [f"Failed to parse results: {str(e)}"],
                    'severity_counts': {},
                    'category_counts': {}
                }
        else:
            results = raw_results

        if not isinstance(results, dict):
            raise ValueError(f"Invalid results format: expected dict, got {type(results)}")

        formatted_response = {
            'summary': {
                'total_files_scanned': len(results.get('paths', {}).get('scanned', [])),
                'total_findings': len(results.get('results', [])),
                'files_scanned': results.get('paths', {}).get('scanned', []),
                'semgrep_version': results.get('version', 'unknown'),
                'scan_status': 'success' if not results.get('errors') else 'completed_with_errors'
            },
            'findings': [],
            'findings_by_severity': {
                'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
            },
            'findings_by_category': {},
            'errors': results.get('errors', [])
        }

        for finding in results.get('results', []):
            try:
                severity = finding.get('extra', {}).get('severity', 'INFO')
                category = finding.get('extra', {}).get('metadata', {}).get('category', 'uncategorized')
                
                formatted_finding = {
                    'id': finding.get('check_id', 'unknown'),
                    'file': finding.get('path', 'unknown'),
                    'line_start': finding.get('start', {}).get('line', 0),
                    'line_end': finding.get('end', {}).get('line', 0),
                    'code_snippet': finding.get('extra', {}).get('lines', ''),
                    'message': finding.get('extra', {}).get('message', ''),
                    'severity': severity,
                    'category': category,
                    'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                    'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                    'fix_recommendations': {
                        'description': finding.get('extra', {}).get('metadata', {}).get('message', ''),
                        'references': finding.get('extra', {}).get('metadata', {}).get('references', [])
                    }
                }

                formatted_response['findings'].append(formatted_finding)
                
                if severity not in formatted_response['findings_by_severity']:
                    formatted_response['findings_by_severity'][severity] = []
                formatted_response['findings_by_severity'][severity].append(formatted_finding)
                
                if category not in formatted_response['findings_by_category']:
                    formatted_response['findings_by_category'][category] = []
                formatted_response['findings_by_category'][category].append(formatted_finding)
                
            except Exception as e:
                logger.error(f"Error processing finding: {str(e)}")
                formatted_response['errors'].append(f"Error processing finding: {str(e)}")

        formatted_response['severity_counts'] = {
            severity: len(findings)
            for severity, findings in formatted_response['findings_by_severity'].items()
        }

        formatted_response['category_counts'] = {
            category: len(findings)
            for category, findings in formatted_response['findings_by_category'].items()
        }

        return formatted_response

    except Exception as e:
        logger.error(f"Error formatting results: {str(e)}")
        return {
            'summary': {
                'total_files_scanned': 0,
                'total_findings': 0,
                'files_scanned': [],
                'semgrep_version': 'unknown',
                'scan_status': 'failed'
            },
            'findings': [],
            'findings_by_severity': {
                'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
            },
            'findings_by_category': {},
            'errors': [f"Failed to format results: {str(e)}"],
            'severity_counts': {},
            'category_counts': {}
        }

try:
    # GitHub Verification
    APP_ID = os.getenv('GITHUB_APP_ID')
    WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
    PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
    
    # GitLab Verification
    GITLAB_APP_ID = os.getenv('GITLAB_APP_ID')
    GITLAB_APP_SECRET = os.getenv('GITLAB_APP_SECRET')
    GITLAB_WEBHOOK_SECRET = os.getenv('GITLAB_WEBHOOK_SECRET')
    GITLAB_CALLBACK_URL = os.getenv('GITLAB_CALLBACK_URL')
    
    if not all([APP_ID, WEBHOOK_SECRET, PRIVATE_KEY]):
        raise ValueError("Missing required GitHub environment variables")
    
    if not all([GITLAB_APP_ID, GITLAB_APP_SECRET, GITLAB_WEBHOOK_SECRET, GITLAB_CALLBACK_URL]):
        raise ValueError("Missing required GitLab environment variables")
    
    formatted_key = format_private_key(PRIVATE_KEY)
    git_integration = GithubIntegration(
        integration_id=int(APP_ID),
        private_key=formatted_key,
    )
    logger.info("GitHub Integration initialized successfully")
    logger.info("GitLab configuration verified successfully")
except Exception as e:
    logger.error(f"Configuration error: {str(e)}")
    raise
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    port = int(os.getenv('PORT', 10000))
    app.run(port=port)