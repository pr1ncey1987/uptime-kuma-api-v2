FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir \
    "python-socketio[client]" \
    websocket-client \
    pyotp \
    python-dotenv

# Copy the bridge script
COPY uptime_kuma.py .

# Expose the bridge port (matches BRIDGE_PORT in .env)
EXPOSE 9911

CMD ["python3", "uptime_kuma.py"]