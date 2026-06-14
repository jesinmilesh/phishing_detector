import os
from app import app
from app.config import Config

if __name__ == '__main__':
    # Initialize screenshots and uploads directories on startup
    os.makedirs(Config.UPLOAD_DIR, exist_ok=True)
    os.makedirs(os.path.join(app.root_path, 'static', 'uploads', 'screenshots'), exist_ok=True)
    app.run(host='0.0.0.0', port=Config.PORT, debug=Config.DEBUG)
