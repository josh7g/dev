import os
import multiprocessing

# Server socket configuration
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
backlog = 2048

# Worker configuration
# Render's starter plan has 512MB RAM, so we keep workers limited
workers = 4  # Good balance for Render's resources
worker_class = 'sync'
threads = 4
worker_connections = 1000

# Timeout configuration
timeout = 120  # Increased timeout for long-running scans
keepalive = 5

# Logging
accesslog = '-'  # Log to stdout
errorlog = '-'   # Log to stderr
loglevel = 'info'
access_log_format = '%({x-forwarded-for}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = 'semgrep-analysis'

# Limits for stability
max_requests = 1000
max_requests_jitter = 50

# Development settings
reload = False  # Disable auto-reload in production
preload_app = True  # Preload app for better performance

# Security settings
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# SSL/TLS settings
forwarded_allow_ips = '*'  # Trust Render's proxy
secure_scheme_headers = {
    'X-FORWARDED-PROTOCOL': 'ssl',
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SSL': 'on'
}

# Error handling
capture_output = True
enable_stdio_inheritance = True

def when_ready(server):
    """Log when server is ready"""
    server.log.info("Server is ready. Spawning workers")

def on_starting(server):
    """Log when server is starting"""
    server.log.info("Server is starting")

def worker_abort(worker):
    """Log worker abort"""
    worker.log.info("Worker received SIGABRT signal")

def post_fork(server, worker):
    """Log worker spawn"""
    server.log.info(f"Worker spawned (pid: {worker.pid})")

# Resource cleanup
graceful_timeout = 30