FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY scripts/ scripts/
COPY config/ config/
COPY data/ data/

EXPOSE 53/udp
EXPOSE 8890

CMD ["python", "scripts/run_dns.py"]
