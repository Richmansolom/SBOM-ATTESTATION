FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    bash \
    jq \
    openssl \
    curl \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

COPY sbom_ui/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

WORKDIR /app/sbom_ui

RUN chmod +x /app/scripts/sign-sbom.sh

ENV PYTHONUNBUFFERED=1
ENV PORT=10000

CMD ["gunicorn", "-b", "0.0.0.0:10000", "app:app"]
