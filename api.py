from flask import Blueprint, jsonify, request
from sqlalchemy import func, desc, create_engine
from sqlalchemy.orm import sessionmaker
from models import db, AnalysisResult
from collections import defaultdict
import os
import ssl
import fnmatch
import logging
from pathlib import Path
from github import Github
from github import GithubIntegration
import asyncio
import logging
from scanner import scan_repository_handler
from scanner import scan_repository_handler, deduplicate_findings
from typing import Dict, Any, List
from datetime import datetime
from scanner import SecurityScanner, ScanConfig
import git
import aiohttp
import json



logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

api = Blueprint('api', __name__, url_prefix='/api/v1')


@api.route('/files', methods=['POST'])
def get_vulnerable_file():
    """Fetch vulnerable file content from GitHub using POST with all parameters in request body"""
    from app import git_integration
    
    # Get data from POST request body
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    # Get required parameters from request body
    owner = request_data.get('owner')
    repo = request_data.get('repo')
    installation_id = request_data.get('installation_id')
    filename = request_data.get('file_name')
    user_id = request_data.get('user_id')
    
    # Validate required parameters
    required_params = {
        'owner': owner,
        'repo': repo,
        'installation_id': installation_id,
        'file_name': filename,
        'user_id': user_id
    }
    
    missing_params = [param for param, value in required_params.items() if not value]
    if missing_params:
        return jsonify({
            'success': False,
            'error': {'message': f'Missing required parameters: {", ".join(missing_params)}'}
        }), 400

    try:
        # Get GitHub token
        installation_token = git_integration.get_access_token(int(installation_id)).token
        gh = Github(installation_token)
        
        repository = gh.get_repo(f"{owner}/{repo}")
        default_branch = repository.default_branch
        latest_commit = repository.get_branch(default_branch).commit
        commit_sha = latest_commit.sha

        # Get file content from GitHub
        try:
            file_content = repository.get_contents(filename, ref=commit_sha)
            content = file_content.decoded_content.decode('utf-8')
            
            return jsonify({
                'success': True,
                'data': {
                    'file': content,
                    'user_id': user_id,
                    'version': commit_sha,
                    'reponame': f"{owner}/{repo}",
                    'filename': filename
                }
            })

        except Exception as e:
            logger.error(f"Error fetching file: {str(e)}")
            return jsonify({
                'success': False,
                'error': {'message': 'File not found or inaccessible'}
            }), 404

    except Exception as e:
        logger.error(f"GitHub API error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500


analysis_bp = Blueprint('analysis', __name__, url_prefix='/api/v1/analysis')

@analysis_bp.route('/<owner>/<repo>/result', methods=['GET'])
def get_analysis_findings(owner: str, repo: str):
    try:
        # Set up database connection with proper SSL
        DATABASE_URL = os.getenv('DATABASE_URL')
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
            # Get query parameters
            page = max(1, int(request.args.get('page', 1)))
            per_page = min(100, max(1, int(request.args.get('limit', 30))))
            severity = request.args.get('severity', '').upper()
            category = request.args.get('category', '')
            file_path = request.args.get('file', '')
            
            repo_name = f"{owner}/{repo}"
            
            # Get latest analysis result
            result = db_session.query(AnalysisResult).filter_by(
                repository_name=repo_name
            ).order_by(
                desc(AnalysisResult.timestamp)
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
                    'repository': {
                        'name': repo_name,
                        'owner': owner,
                        'repo': repo
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

@api.route('/users/severity-counts', methods=['POST'])
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

        DATABASE_URL = os.getenv('DATABASE_URL')
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
            all_analyses = db_session.query(AnalysisResult).filter(
                AnalysisResult.user_id == user_id,
                AnalysisResult.status == 'completed',
                AnalysisResult.results.isnot(None)
            ).order_by(AnalysisResult.timestamp.desc()).all()

            logger.info(f"Found {len(all_analyses)} total analyses")

            # Get latest analysis per repository
            latest_analyses = {}
            for analysis in all_analyses:
                repo_name = analysis.repository_name
                if repo_name not in latest_analyses:
                    latest_analyses[repo_name] = analysis
                    logger.info(f"Latest analysis for {repo_name}:")
                    logger.info(f"- Timestamp: {analysis.timestamp}")
                    logger.info(f"- Results: {analysis.results}")
                    logger.info(f"- Summary: {analysis.results.get('summary', {})}")

            if not latest_analyses:
                return jsonify({
                    'success': False,
                    'error': {'message': 'No analyses found for this user'}
                }), 404

            repository_data = {}
            total_severity_counts = defaultdict(int)
            total_findings = 0
            latest_scan_time = None

            for repo_name, analysis in latest_analyses.items():
                results = analysis.results
                logger.info(f"\nProcessing {repo_name}:")
                logger.info(f"Raw results: {results}")
                
                summary = results.get('summary', {})
                logger.info(f"Summary data: {summary}")
                
                severity_counts = summary.get('severity_counts', {})
                logger.info(f"Severity counts: {severity_counts}")
                
                repo_findings = summary.get('total_findings', 0)
                logger.info(f"Total findings: {repo_findings}")

                latest_scan_time = max(latest_scan_time, analysis.timestamp) if latest_scan_time else analysis.timestamp
                
                repository_data[repo_name] = {
                    'name': repo_name,
                    'severity_counts': severity_counts
                }

                # Update totals
                for severity, count in severity_counts.items():
                    total_severity_counts[severity] += count
                    logger.info(f"Added {count} {severity} findings to total")
                total_findings += repo_findings

            logger.info("\nFinal totals:")
            logger.info(f"Total findings: {total_findings}")
            logger.info(f"Total severity counts: {dict(total_severity_counts)}")
            logger.info(f"Repository data: {repository_data}")

            return jsonify({
                'success': True,
                'data': {
                    'user_id': user_id,
                    'total_findings': total_findings,
                    'total_repositories': len(repository_data),
                    'severity_counts': dict(total_severity_counts),
                    'repositories': repository_data,
                    'metadata': {
                        'last_scan': latest_scan_time.isoformat() if latest_scan_time else None,
                        'scans_analyzed': len(repository_data)
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
    
    
@api.route('/users/<user_id>/top-vulnerabilities', methods=['GET'])
def get_top_vulnerabilities(user_id):
    try:
        analyses = AnalysisResult.query.filter(
            AnalysisResult.user_id == user_id,
            AnalysisResult.status == 'completed',
            AnalysisResult.results.isnot(None)
        ).order_by(AnalysisResult.timestamp.desc()).all()

        if not analyses:
            return jsonify({
                'success': False,
                'error': {'message': 'No analyses found'}
            }), 404

        # Track statistics
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        repo_counts = defaultdict(int)
        unique_vulns = {}

        for analysis in analyses:
            findings = analysis.results.get('findings', [])
            repo_name = analysis.repository_name
            
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
                        'repository': {
                            'name': repo_name.split('/')[-1],
                            'full_name': repo_name,
                            'analyzed_at': analysis.timestamp.isoformat()
                        }
                    }
                    
                    severity_counts[finding.get('severity')] += 1
                    category_counts[finding.get('category')] += 1
                    repo_counts[repo_name] += 1

        return jsonify({
            'success': True,
            'data': {
                'metadata': {
                    'user_id': user_id,
                    'total_vulnerabilities': len(unique_vulns),
                    'total_repositories': len(repo_counts),
                    'severity_breakdown': severity_counts,
                    'category_breakdown': category_counts,
                    'repository_breakdown': repo_counts,
                    'last_scan': analyses[0].timestamp.isoformat() if analyses else None,
                    'repository': None  # For compatibility with existing format
                },
                'vulnerabilities': list(unique_vulns.values())
            }
        })

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
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

@api.route('/scan', methods=['POST'])
async def trigger_repository_scan():
    """Trigger a semgrep security scan for a repository and get reranking"""
    from app import git_integration
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    # Get data from POST request body
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    # Get required parameters
    owner = request_data.get('owner')
    repo = request_data.get('repo')
    installation_id = request_data.get('installation_id')
    user_id = request_data.get('user_id')
    
    # Validate required parameters
    required_params = {
        'owner': owner,
        'repo': repo,
        'installation_id': installation_id,
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

    # Set up database connection with SSL
    DATABASE_URL = os.getenv('DATABASE_URL')
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
        analysis = None
        try:
            # Get GitHub token
            try:
                installation_token = git_integration.get_access_token(int(installation_id)).token
            except Exception as token_error:
                return {
                    'success': False,
                    'error': {
                        'message': 'GitHub authentication failed',
                        'code': 'AUTH_ERROR',
                        'details': str(token_error)
                    }
                }, 401

            config = ScanConfig()
            
            # Create initial analysis record
            analysis = AnalysisResult(
                repository_name=f"{owner}/{repo}",
                user_id=user_id,
                status='in_progress'
            )
            db_session.add(analysis)
            db_session.commit()
            logger.info(f"Created analysis record with ID: {analysis.id}")

            # Run the security scan
            async with SecurityScanner(config=config, db_session=db_session) as scanner:
                scan_results = await scanner.scan_repository(
                    repo_url=f"https://github.com/{owner}/{repo}",
                    installation_token=installation_token,
                    user_id=user_id
                )

                if scan_results.get('success'):
                    # Store original scan results
                    analysis.results = scan_results.get('data')
                    
                    # Get findings and add IDs
                    findings = scan_results.get('data', {}).get('findings', [])
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
                            'repository': f"{owner}/{repo}",
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
                                # Only log the LLM response
                                logger.info(f"LLM Response: {response_data.get('llm_response', '')}")
                                
                                reranked_ids = extract_ids_from_llm_response(response_data)
                                if reranked_ids:
                                    findings_map = {finding['ID']: finding for finding in findings}
                                    reordered_findings = [findings_map[id] for id in reranked_ids]
                                    
                                    # Update analysis with reordered findings
                                    analysis.rerank = reordered_findings
                                    analysis.status = 'completed'
                                    db_session.commit()
                                    
                                    # Add reranked results to response
                                    scan_results['data']['reranked_findings'] = reordered_findings
                                else:
                                    # Fall back to original order
                                    logger.warning("Could not extract IDs from LLM response, using original order")
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
            if analysis:
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

@analysis_bp.route('/<owner>/<repo>/reranked', methods=['GET'])
def get_reranked_findings(owner: str, repo: str):
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        import os

        DATABASE_URL = os.getenv('DATABASE_URL')
        if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

        # Create engine with SSL configuration
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

        # Create a session
        Session = sessionmaker(bind=engine)
        session = Session()

        try:
            # Get latest analysis result
            result = session.query(AnalysisResult).filter_by(
                repository_name=f"{owner}/{repo}"
            ).order_by(
                desc(AnalysisResult.timestamp)
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

            # Return just the reranked findings
            return jsonify(result.rerank)
            
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