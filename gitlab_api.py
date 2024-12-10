#gitlab_api.py
from flask import Blueprint, jsonify, request,redirect
from sqlalchemy import func, desc, create_engine
from sqlalchemy.orm import sessionmaker
from models import db, GitLabAnalysisResult
from collections import defaultdict
import os
import ssl
import fnmatch
import logging
import aiohttp
import traceback
from pathlib import Path
import asyncio
import logging
from gitlab_scanner import scan_gitlab_repository_handler, deduplicate_findings,GitLabScanConfig,GitLabSecurityScanner
from typing import Dict, Any, List
from datetime import datetime
import json
import requests
from flask import current_app

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

gitlab_api = Blueprint('gitlab_api', __name__, url_prefix='/api/v1/gitlab')

@gitlab_api.route('/install', methods=['GET'])
def install_app():
    """Redirect to GitLab OAuth page"""
    gitlab_auth_url = (
        f"https://gitlab.com/oauth/authorize?"
        f"client_id={os.getenv('GITLAB_APP_ID')}&"
        f"redirect_uri={os.getenv('GITLAB_CALLBACK_URL')}&"
        f"response_type=code&"
        f"scope=api+read_repository"
    )
    return redirect(gitlab_auth_url)

@gitlab_api.route('/oauth/callback')
async def gitlab_oauth_callback():
    """Handle GitLab OAuth callback and return repositories list"""
    try:
        code = request.args.get('code')
        if not code:
            return jsonify({'error': 'No code provided'}), 400

        # Exchange code for access token
        data = {
            'client_id': os.getenv('GITLAB_APP_ID'),
            'client_secret': os.getenv('GITLAB_APP_SECRET'),
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': os.getenv('GITLAB_CALLBACK_URL')
        }

        # Get access token
        response = requests.post('https://gitlab.com/oauth/token', data=data)
        if response.status_code != 200:
            logger.error(f"Failed to get access token: {response.text}")
            return jsonify({'error': 'Failed to get access token'}), 400

        token_data = response.json()
        access_token = token_data['access_token']

        # Get user information
        headers = {'Authorization': f"Bearer {access_token}"}
        user_response = requests.get('https://gitlab.com/api/v4/user', headers=headers)
        
        if user_response.status_code != 200:
            logger.error(f"Failed to get user information: {user_response.text}")
            return jsonify({'error': 'Failed to get user information'}), 400

        user_data = user_response.json()
        user_id = str(user_data['id'])

        # Get user's repositories
        repos_response = requests.get(
            'https://gitlab.com/api/v4/projects',
            headers=headers,
            params={'membership': True, 'min_access_level': 30}  # 30 = Developer access
        )

        if repos_response.status_code == 200:
            repositories = repos_response.json()
            
            # Format repository data
            formatted_repos = [{
                'id': repo['id'],
                'name': repo['name'],
                'full_name': repo['path_with_namespace'],
                'url': repo['web_url'],
                'description': repo['description'],
                'default_branch': repo['default_branch'],
                'visibility': repo['visibility'],
                'created_at': repo['created_at'],
                'last_activity_at': repo['last_activity_at']
            } for repo in repositories]

            return jsonify({
                'success': True,
                'data': {
                    'user': {
                        'id': user_id,
                        'name': user_data['name'],
                        'username': user_data['username']
                    },
                    'access_token': access_token,
                    'repositories': formatted_repos
                }
            })

        return jsonify({'error': 'Failed to fetch repositories'}), 400

    except Exception as e:
        logger.error(f"GitLab OAuth error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@gitlab_api.route('/repositories/<repo_id>/scan', methods=['POST'])
async def trigger_specific_repository_scan(repo_id):
    """Trigger a security scan for a specific repository with LLM reranking"""
    logger.info(f"Starting scan for repository ID: {repo_id}")
    db_session = None
    analysis = None
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': {'message': 'Request body is required'}
            }), 400

        access_token = data.get('access_token')
        user_id = data.get('user_id')
        
        logger.info(f"Fetching repository details for ID: {repo_id}")
        headers = {'Authorization': f"Bearer {access_token}"}
        repo_response = requests.get(
            f'https://gitlab.com/api/v4/projects/{repo_id}',
            headers=headers
        )

        if repo_response.status_code != 200:
            logger.error(f"Failed to fetch repository details: {repo_response.text}")
            return jsonify({
                'success': False,
                'error': {'message': 'Repository not found or inaccessible'}
            }), 404

        repo_data = repo_response.json()
        project_url = repo_data['web_url']
        logger.info(f"Successfully fetched repository details for: {project_url}")

        # Create database session
        engine = db.get_engine(current_app, bind='gitlab')
        Session = sessionmaker(bind=engine)
        db_session = Session()

        try:
            # Create initial analysis record
            analysis = GitLabAnalysisResult(
                project_id=str(repo_id),
                project_url=project_url,
                user_id=user_id,
                status='in_progress',
                timestamp=datetime.utcnow()
            )
            db_session.add(analysis)
            db_session.commit()
            logger.info(f"Created analysis record with ID: {analysis.id}")

            # Trigger the scan
            logger.info("Starting repository scan...")
            scan_result = await scan_gitlab_repository_handler(
                project_url=project_url,
                access_token=access_token,
                user_id=user_id,
                db_session=db_session
            )
            
            logger.info(f"Scan completed with success status: {scan_result.get('success', False)}")

            if scan_result.get('success'):
                # Get findings and add IDs
                findings = scan_result['data'].get('findings', [])
                for idx, finding in enumerate(findings, 1):
                    finding['ID'] = idx

                # Prepare simplified data for LLM
                llm_data = {
                    'findings': [{
                        "ID": finding["ID"],
                        "file": finding["file"],
                        "code_snippet": finding["code_snippet"],
                        "message": finding["message"],
                        "severity": finding["severity"]
                    } for finding in findings],
                    'metadata': {
                        'project_id': repo_id,
                        'user_id': user_id,
                        'timestamp': datetime.utcnow().isoformat(),
                        'scan_id': analysis.id
                    }
                }

                # Send to AI reranking service
                AI_RERANK_URL = os.getenv('RERANK_API_URL')
                if not AI_RERANK_URL:
                    raise ValueError("RERANK_API_URL not configured")

                async with aiohttp.ClientSession() as session:
                    async with session.post(AI_RERANK_URL, json=llm_data) as response:
                        if response.status == 200:
                            response_data = await response.json()
                            logger.info(f"LLM Response: {response_data.get('llm_response', '')}")
                            
                            reranked_ids = extract_ids_from_llm_response(response_data)
                            if reranked_ids:
                                findings_map = {finding['ID']: finding for finding in findings}
                                reordered_findings = [findings_map[id] for id in reranked_ids]
                                
                                # Store original results
                                results_data = {
                                    'findings': findings,
                                    'summary': scan_result['data'].get('summary', {}),
                                    'metadata': scan_result['data'].get('metadata', {}),
                                    'repository_info': scan_result['data'].get('repository_info', {}),
                                    'timestamp': datetime.utcnow().isoformat(),
                                    'project_id': repo_id,
                                    'project_url': project_url,
                                    'user_id': user_id
                                }
                                
                                # Update analysis with both original and reranked results
                                analysis.status = 'completed'
                                analysis.results = results_data
                                analysis.rerank = reordered_findings
                                db_session.add(analysis)
                                db_session.commit()
                                
                                # Add reranked findings to response
                                scan_result['data']['reranked_findings'] = reordered_findings
                            else:
                                logger.warning("Could not extract IDs from LLM response, using original order")
                                analysis.status = 'completed'
                                analysis.results = scan_result['data']
                                analysis.rerank = findings
                                db_session.add(analysis)
                                db_session.commit()
                                scan_result['data']['reranked_findings'] = findings
                        else:
                            logger.error(f"AI reranking failed: {await response.text()}")
                            analysis.status = 'reranking_failed'
                            analysis.error = "Reranking failed"
                            db_session.commit()

                return jsonify({
                    'success': True,
                    'data': {
                        'analysis_id': analysis.id,
                        'repository': repo_data['path_with_namespace'],
                        'scan_result': scan_result,
                        'status': analysis.status
                    }
                })

            else:
                logger.error(f"Scan failed with error: {scan_result.get('error', {})}")
                analysis.status = 'failed'
                analysis.error = str(scan_result.get('error', {}))
                db_session.commit()
                return jsonify(scan_result), 500

        except Exception as inner_e:
            logger.error(f"Error during scan process: {str(inner_e)}")
            logger.error(traceback.format_exc())
            if analysis:
                analysis.status = 'failed'
                analysis.error = str(inner_e)
                db_session.commit()
            raise

    except Exception as e:
        logger.error(f"Error in scan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500
        
    finally:
        if db_session:
            db_session.close()
            logger.info("Database session closed")

    


@gitlab_api.route('/repositories', methods=['GET'])
def list_repositories():
    """List repositories accessible to the authenticated user"""
    access_token = request.headers.get('Authorization')
    if not access_token:
        return jsonify({'error': 'Authorization token required'}), 401

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json'
    }
    
    response = requests.get(
        'https://gitlab.com/api/v4/projects',
        headers=headers,
        params={'membership': True}
    )
    
    if response.status_code == 200:
        repositories = response.json()
        return jsonify({
            'success': True,
            'data': repositories
        })
    return jsonify({'error': 'Failed to fetch repositories'}), response.status_code

@gitlab_api.route('/files', methods=['POST'])
def get_vulnerable_file():
    """Fetch vulnerable file content from GitLab using POST with all parameters in request body"""
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    project_id = request_data.get('project_id')
    file_path = request_data.get('file_path')
    access_token = request_data.get('access_token')
    user_id = request_data.get('user_id')
    
    required_params = {
        'project_id': project_id,
        'file_path': file_path,
        'access_token': access_token,
        'user_id': user_id
    }
    
    missing_params = [param for param, value in required_params.items() if not value]
    if missing_params:
        return jsonify({
            'success': False,
            'error': {'message': f'Missing required parameters: {", ".join(missing_params)}'}
        }), 400

    try:
        headers = {
            'PRIVATE-TOKEN': access_token,
            'Accept': 'application/json'
        }
        
        # Get default branch
        project_url = f"https://gitlab.com/api/v4/projects/{project_id}"
        project_response = requests.get(project_url, headers=headers)
        if project_response.status_code != 200:
            return jsonify({
                'success': False,
                'error': {'message': 'Failed to get project information'}
            }), 404
            
        default_branch = project_response.json().get('default_branch', 'main')
        
        # Get file content
        file_url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/files/{file_path}/raw"
        params = {'ref': default_branch}
        
        file_response = requests.get(file_url, headers=headers, params=params)
        if file_response.status_code != 200:
            return jsonify({
                'success': False,
                'error': {'message': 'File not found or inaccessible'}
            }), 404

        return jsonify({
            'success': True,
            'data': {
                'file': file_response.text,
                'user_id': user_id,
                'version': default_branch,
                'project_id': project_id,
                'file_path': file_path
            }
        })

    except Exception as e:
        logger.error(f"GitLab API error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500

@gitlab_api.route('/projects/<project_id>/analysis/results', methods=['GET'])
def get_analysis_findings(project_id: str):
    try:
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('limit', 30))))
        severity = request.args.get('severity', '').upper()
        category = request.args.get('category', '')
        file_path = request.args.get('file', '')

        DATABASE_URL = os.getenv('GITLAB_DATABASE_URL')
        if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

        engine = create_engine(
            DATABASE_URL,
            connect_args={
                'sslmode': 'require',
                'ssl_min_protocol_version': 'TLSv1.2'
            },
            pool_pre_ping=True,
            pool_recycle=300,
            pool_timeout=30
        )

        Session = sessionmaker(bind=engine)
        db_session = Session()

        try:
            # Get latest analysis result
            result = db_session.query(GitLabAnalysisResult).filter_by(
                project_id=project_id
            ).order_by(
                desc(GitLabAnalysisResult.timestamp)
            ).first()
            
            if not result:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'No analysis found',
                        'code': 'ANALYSIS_NOT_FOUND'
                    }
                }), 404

            # Get findings from the results
            findings = result.results.get('findings', [])
            
            # Apply filters
            if severity:
                findings = [f for f in findings if f.get('severity', '').upper() == severity]
            if category:
                findings = [f for f in findings if f.get('category', '').lower() == category.lower()]
            if file_path:
                findings = [f for f in findings if file_path in f.get('file', '')]
            
            # Get total count before pagination
            total_findings = len(findings)
            
            # Apply pagination
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            paginated_findings = findings[start_idx:end_idx]
            
            # Get unique values for filters
            all_severities = sorted(set(f.get('severity', '').upper() for f in findings))
            all_categories = sorted(set(f.get('category', '').lower() for f in findings))
            
            # Get summary and metadata
            summary = result.results.get('summary', {})
            metadata = result.results.get('metadata', {})
            
            return jsonify({
                'success': True,
                'data': {
                    'project': {
                        'id': project_id,
                        'url': result.project_url
                    },
                    'metadata': {
                        'analysis_id': result.id,
                        'timestamp': result.timestamp.isoformat(),
                        'status': result.status,
                        'duration_seconds': metadata.get('scan_duration_seconds')
                    },
                    'summary': {
                        'files_scanned': summary.get('files_scanned', 0),
                        'files_with_findings': summary.get('files_with_findings', 0),
                        'skipped_files': summary.get('skipped_files', 0),
                        'partially_scanned': summary.get('partially_scanned', 0),
                        'total_findings': summary.get('total_findings', total_findings),
                        'severity_counts': summary.get('severity_counts', {}),
                        'category_counts': summary.get('category_counts', {})
                    },
                    'findings': paginated_findings,
                    'pagination': {
                        'current_page': page,
                        'total_pages': (total_findings + per_page - 1) // per_page,
                        'total_items': total_findings,
                        'per_page': per_page
                    },
                    'filters': {
                        'available_severities': all_severities,
                        'available_categories': all_categories
                    }
                }
            })
            
        finally:
            db_session.close()
            
    except Exception as e:
        logger.error(f"Error getting findings: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR'
            }
        }), 500

@gitlab_api.route('/users/severity-counts', methods=['POST'])
def get_user_severity_counts():
    try:
        request_data = request.get_json()
        if not request_data or 'user_id' not in request_data:
            return jsonify({
                'success': False,
                'error': {'message': 'user_id is required'}
            }), 400
        
        user_id = request_data['user_id']
        logger.info(f"Processing severity counts for user_id: {user_id}")

        DATABASE_URL = os.getenv('GITLAB_DATABASE_URL')
        if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

        engine = create_engine(
            DATABASE_URL,
            connect_args={
                'sslmode': 'require',
                'ssl_min_protocol_version': 'TLSv1.2'
            },
            pool_pre_ping=True,
            pool_recycle=300,
            pool_timeout=30
        )

        Session = sessionmaker(bind=engine)
        db_session = Session()

        try:
            # Get all completed analyses
            all_analyses = db_session.query(GitLabAnalysisResult).filter(
                GitLabAnalysisResult.user_id == user_id,
                GitLabAnalysisResult.status == 'completed',
                GitLabAnalysisResult.results.isnot(None)
            ).order_by(GitLabAnalysisResult.timestamp.desc()).all()

            # Get latest analysis per project
            latest_analyses = {}
            for analysis in all_analyses:
                project_id = analysis.project_id
                if project_id not in latest_analyses:
                    latest_analyses[project_id] = analysis

            if not latest_analyses:
                return jsonify({
                    'success': False,
                    'error': {'message': 'No analyses found for this user'}
                }), 404

            project_data = {}
            total_severity_counts = defaultdict(int)
            total_findings = 0
            latest_scan_time = None

            for project_id, analysis in latest_analyses.items():
                results = analysis.results
                summary = results.get('summary', {})
                severity_counts = summary.get('severity_counts', {})
                project_findings = summary.get('total_findings', 0)

                latest_scan_time = max(latest_scan_time, analysis.timestamp) if latest_scan_time else analysis.timestamp
                
                project_data[project_id] = {
                    'id': project_id,
                    'url': analysis.project_url,
                    'severity_counts': severity_counts
                }

                # Update totals
                for severity, count in severity_counts.items():
                    total_severity_counts[severity] += count
                total_findings += project_findings

            return jsonify({
                'success': True,
                'data': {
                    'user_id': user_id,
                    'total_findings': total_findings,
                    'total_projects': len(project_data),
                    'severity_counts': dict(total_severity_counts),
                    'projects': project_data,
                    'metadata': {
                        'last_scan': latest_scan_time.isoformat() if latest_scan_time else None,
                        'scans_analyzed': len(project_data)
                    }
                }
            })

        finally:
            db_session.close()

    except Exception as e:
        logger.error(f"Error getting severity counts: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500

@gitlab_api.route('/scan', methods=['POST'])
async def trigger_general_repository_scan():
    """Trigger a semgrep security scan for a GitLab repository"""
    # Get data from POST request body
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    # Get required parameters
    project_id = request_data.get('project_id')
    project_url = request_data.get('project_url')
    access_token = request_data.get('access_token')
    user_id = request_data.get('user_id')
    
    # Validate required parameters
    required_params = {
        'project_id': project_id,
        'project_url': project_url,
        'access_token': access_token,
        'user_id': user_id
    }
    
    missing_params = [param for param, value in required_params.items() if not value]
    if missing_params:
        return jsonify({
            'success': False,
            'error': {
                'message': f'Missing required parameters: {", ".join(missing_params)}',
                'code': 'INVALID_PARAMETERS'
            }
        }), 400

    # Set up database connection
    DATABASE_URL = os.getenv('GITLAB_DATABASE_URL')
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

    engine = create_engine(
        DATABASE_URL,
        connect_args={
            'sslmode': 'require',
            'ssl_min_protocol_version': 'TLSv1.2'
        },
        pool_pre_ping=True,
        pool_recycle=300,
        pool_timeout=30
    )

    Session = sessionmaker(bind=engine)
    db_session = Session()

    async def run_scan():
        try:
            # Create initial analysis record
            analysis = GitLabAnalysisResult(
                project_id=project_id,
                project_url=project_url,
                user_id=user_id,
                status='in_progress'
            )
            db_session.add(analysis)
            db_session.commit()
            logger.info(f"Created analysis record with ID: {analysis.id}")

            # Run the security scan
            scan_results = await scan_gitlab_repository_handler(
                project_url=project_url,
                access_token=access_token,
                user_id=user_id,
                db_session=db_session
            )

            if scan_results.get('success'):
                findings = scan_results.get('data', {}).get('findings', [])
                
                # Add IDs to findings
                for idx, finding in enumerate(findings, 1):
                    finding['ID'] = idx

                # Prepare data for AI reranking
                llm_data = {
                    'findings': [{
                        "ID": finding["ID"],
                        "file": finding["file"],
                        "code_snippet": finding["code_snippet"],
                        "message": finding["message"],
                        "severity": finding["severity"]
                    } for finding in findings],
                    'metadata': {
                        'project_id': project_id,
                        'user_id': user_id,
                        'timestamp': datetime.utcnow().isoformat(),
                        'scan_id': analysis.id
                    }
                }

                # Send to AI reranking service
                AI_RERANK_URL = os.getenv('RERANK_API_URL')
                if not AI_RERANK_URL:
                    raise ValueError("RERANK_API_URL not configured")

                async with aiohttp.ClientSession() as session:
                    async with session.post(AI_RERANK_URL, json=llm_data) as response:
                        if response.status == 200:
                            response_data = await response.json()
                            reranked_ids = extract_ids_from_llm_response(response_data)
                            
                            if reranked_ids:
                                findings_map = {finding['ID']: finding for finding in findings}
                                reordered_findings = [findings_map[id] for id in reranked_ids]
                                
                                analysis.rerank = reordered_findings
                                analysis.status = 'completed'
                                db_session.commit()
                                
                                scan_results['data']['reranked_findings'] = reordered_findings
                            else:
                                analysis.rerank = findings
                                analysis.status = 'completed'
                                db_session.commit()
                                scan_results['data']['reranked_findings'] = findings
                        else:
                            logger.error(f"AI reranking failed: {await response.text()}")
                            analysis.status = 'reranking_failed'
                            analysis.error = "Reranking failed"
                            db_session.commit()

                return scan_results, 200
            else:
                analysis.status = 'failed'
                analysis.error = scan_results.get('error', {}).get('message', 'Scan failed')
                db_session.commit()
                return scan_results, 500

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            if 'analysis' in locals():
                analysis.status = 'failed'
                analysis.error = str(e)
                db_session.commit()
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'UNEXPECTED_ERROR'
                }
            }, 500
        finally:
            db_session.close()

    # Run the async function
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results, status_code = await run_scan()
        return jsonify(results), status_code
    except Exception as e:
        logger.error(f"Error in async execution: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Error in async execution',
                'code': 'ASYNC_ERROR',
                'details': str(e)
            }
        }), 500

def extract_ids_from_llm_response(response_data):
    """Extract IDs from LLM response text"""
    try:
        if isinstance(response_data, dict) and 'llm_response' in response_data:
            response_text = response_data['llm_response']
            import re
            array_match = re.search(r'\[([\d,\s]+)\]', response_text)
            if array_match:
                id_string = array_match.group(1)
                return [int(id.strip()) for id in id_string.split(',')]
        return None
    except Exception as e:
        logger.error(f"Error extracting IDs from LLM response: {str(e)}")
        return None

@gitlab_api.route('/projects/<project_id>/analysis/reranked', methods=['GET'])
def get_reranked_findings(project_id: str):
    try:
        DATABASE_URL = os.getenv('GITLAB_DATABASE_URL')
        if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

        engine = create_engine(
            DATABASE_URL,
            connect_args={
                'sslmode': 'require',
                'ssl_min_protocol_version': 'TLSv1.2'
            },
            pool_pre_ping=True,
            pool_recycle=300,
            pool_timeout=30
        )

        Session = sessionmaker(bind=engine)
        session = Session()

        try:
            # Get latest analysis result
            result = session.query(GitLabAnalysisResult).filter_by(
                project_id=project_id
            ).order_by(
                desc(GitLabAnalysisResult.timestamp)
            ).first()
            
            if not result:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'No analysis found',
                        'code': 'ANALYSIS_NOT_FOUND'
                    }
                }), 404

            if not result.rerank:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'No reranked results available',
                        'code': 'NO_RERANK_RESULTS'
                    }
                }), 404

            return jsonify({
                'success': True,
                'data': result.rerank
            })
            
        finally:
            session.close()
            
    except Exception as e:
        logger.error(f"Error getting reranked findings: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR'
            }
        }), 500

@gitlab_api.route('/users/<user_id>/top-vulnerabilities', methods=['GET'])
def get_top_vulnerabilities(user_id):
    try:
        DATABASE_URL = os.getenv('GITLAB_DATABASE_URL')
        if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

        engine = create_engine(
            DATABASE_URL,
            connect_args={
                'sslmode': 'require',
                'ssl_min_protocol_version': 'TLSv1.2'
            },
            pool_pre_ping=True,
            pool_recycle=300,
            pool_timeout=30
        )

        Session = sessionmaker(bind=engine)
        session = Session()

        try:
            analyses = session.query(GitLabAnalysisResult).filter(
                GitLabAnalysisResult.user_id == user_id,
                GitLabAnalysisResult.status == 'completed',
                GitLabAnalysisResult.results.isnot(None)
            ).order_by(GitLabAnalysisResult.timestamp.desc()).all()

            if not analyses:
                return jsonify({
                    'success': False,
                    'error': {'message': 'No analyses found'}
                }), 404

            # Track statistics
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            project_counts = defaultdict(int)
            unique_vulns = {}

            for analysis in analyses:
                findings = analysis.results.get('findings', [])
                project_id = analysis.project_id
                
                for finding in findings:
                    vuln_id = finding.get('id')
                    if vuln_id not in unique_vulns:
                        unique_vulns[vuln_id] = {
                            'vulnerability_id': vuln_id,
                            'severity': finding.get('severity'),
                            'category': finding.get('category'),
                            'message': finding.get('message'),
                            'code_snippet': finding.get('code_snippet'),
                            'file': finding.get('file'),
                            'line_range': {
                                'start': finding.get('line_start'),
                                'end': finding.get('line_end')
                            },
                            'security_references': {
                                'cwe': finding.get('cwe', []),
                                'owasp': finding.get('owasp', [])
                            },
                            'fix_recommendations': {
                                'description': finding.get('fix_recommendations', ''),
                                'references': finding.get('references', [])
                            },
                            'project': {
                                'id': project_id,
                                'url': analysis.project_url,
                                'analyzed_at': analysis.timestamp.isoformat()
                            }
                        }
                        
                        severity_counts[finding.get('severity')] += 1
                        category_counts[finding.get('category')] += 1
                        project_counts[project_id] += 1

            return jsonify({
                'success': True,
                'data': {
                    'metadata': {
                        'user_id': user_id,
                        'total_vulnerabilities': len(unique_vulns),
                        'total_projects': len(project_counts),
                        'severity_breakdown': dict(severity_counts),
                        'category_breakdown': dict(category_counts),
                        'project_breakdown': dict(project_counts),
                        'last_scan': analyses[0].timestamp.isoformat() if analyses else None
                    },
                    'vulnerabilities': list(unique_vulns.values())
                }
            })

        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error getting top vulnerabilities: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500

def deduplicate_findings(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Remove duplicate findings from scan results based on multiple criteria"""
    if not scan_results.get('success') or 'data' not in scan_results:
        return scan_results

    original_summary = scan_results['data'].get('summary', {})
    findings = scan_results['data'].get('findings', [])
    
    if not findings:
        return scan_results
    
    seen_findings = set()
    deduplicated_findings = []
    
    for finding in findings:
        finding_signature = (
            finding.get('file', ''),
            finding.get('line_start', 0),
            finding.get('line_end', 0),
            finding.get('category', ''),
            finding.get('severity', ''),
            finding.get('code_snippet', '')
        )
        
        if finding_signature not in seen_findings:
            seen_findings.add(finding_signature)
            deduplicated_findings.append(finding)
    
    severity_counts = defaultdict(int)
    category_counts = defaultdict(int)
    
    for finding in deduplicated_findings:
        severity = finding.get('severity', 'UNKNOWN')
        category = finding.get('category', 'unknown')
        severity_counts[severity] += 1
        category_counts[category] += 1
    
    updated_summary = {
        'total_findings': len(deduplicated_findings),
        'files_scanned': original_summary.get('files_scanned', 0),
        'files_with_findings': original_summary.get('files_with_findings', 0),
        'skipped_files': original_summary.get('skipped_files', 0),
        'partially_scanned': original_summary.get('partially_scanned', 0),
        'severity_counts': dict(severity_counts),
        'category_counts': dict(category_counts),
        'deduplication_info': {
            'original_count': len(findings),
            'deduplicated_count': len(deduplicated_findings),
            'duplicates_removed': len(findings) - len(deduplicated_findings)
        }
    }
    
    scan_results['data']['findings'] = deduplicated_findings
    scan_results['data']['summary'] = updated_summary
    
    return scan_results