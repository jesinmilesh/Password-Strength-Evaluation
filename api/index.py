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
    requests to /api/index, preserving original endpoint paths (/evaluate, /generate, etc.)
    and avoiding 404/405 errors.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '')

        # Check if original incoming path was captured in Vercel headers
        orig = (
            environ.get('HTTP_X_MATCHED_PATH') or
            environ.get('RAW_URI') or
            environ.get('REQUEST_URI') or
            ''
        )
        if orig:
            orig_clean = orig.split('?')[0]
            if orig_clean and not orig_clean.startswith('/api/'):
                path = orig_clean
                environ['PATH_INFO'] = orig_clean

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
