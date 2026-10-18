# Gateway API + demo page. Ubuntu's own packages are used because they come pre-built for
# s390x; pip would have to compile `cryptography` from source on LinuxONE.
#   docker build -t shield .        (or: podman build -t shield .)
#   docker run --network host -e SHIELD_BACKEND=llm -e LOOP_LLM_BASE_URL=http://127.0.0.1:8080/v1 shield
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-cryptography \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY shield/ shield/
COPY static/ static/
COPY api.py .
ENV API_HOST=0.0.0.0 API_PORT=8000 PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["python3", "api.py"]
