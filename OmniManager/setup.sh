#!/usr/bin/env bash
# OmniManager first-run setup
# Run once after cloning: bash setup.sh

set -e
cd "$(dirname "$0")"

echo "==> Checking .env..."
if [ ! -f .env ]; then
  cp .env.example .env
  echo "    Created .env from .env.example — edit SECRET_KEY and ADMIN_PASSWORD before running in production."
fi

echo "==> Installing dependencies..."
pip install -r requirements.txt

echo "==> Initialising database migrations..."
if [ ! -d migrations ]; then
  flask db init
  echo "    Migrations folder created."
fi

flask db migrate -m "initial schema" 2>/dev/null || echo "    (no new migrations detected)"
flask db upgrade
echo "    Database up to date."

echo ""
echo "Setup complete. Start the server with:"
echo "  python run.py"
echo ""
echo "Or for production (requires eventlet and gunicorn):"
echo "  SOCKETIO_ASYNC_MODE=eventlet gunicorn --worker-class eventlet -w 1 'run:app'"
