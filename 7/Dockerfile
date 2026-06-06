FROM python:3.12-slim

# Non-root user for safety
RUN useradd -ms /bin/bash appuser

WORKDIR /app

# Install dependencies first (layer-cache friendly)
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app/ /app/

# Writable directory for logs
RUN mkdir -p /app/logs && chown -R appuser:appuser /app/logs

USER appuser

ENV PYTHONUNBUFFERED=1

EXPOSE 5000

# Autostart the Flask web server
CMD ["python", "app.py"]
