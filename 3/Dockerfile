FROM python:3.12-slim

RUN useradd -ms /bin/bash appuser

WORKDIR /app
COPY app/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app /app
COPY sql /docker-entrypoint-initdb.d-readonly

RUN mkdir -p /logs && chown -R appuser:appuser /logs
USER appuser

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "app.py"]
