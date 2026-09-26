import os
import sys

# Ensure the root project directory is on sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Import the Flask application instance
from app import app

class VercelPathMiddleware:
    """
    Normalizes PATH_INFO when Vercel serverless rewrites route incoming
    requests to /api/index or /api/index.py, preventing Flask 404 Not Found errors.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '')
        for prefix in ('/api/index.py', '/api/index', '/api'):
            if path == prefix:
                environ['PATH_INFO'] = '/'
                break
            elif path.startswith(prefix + '/'):
                environ['PATH_INFO'] = path[len(prefix):]
                break
        return self.wsgi_app(environ, start_response)

# Wrap Flask wsgi_app with the path normalization middleware
app.wsgi_app = VercelPathMiddleware(app.wsgi_app)
