# Black Duck -> SVM sync test runner.
#   docker build -t bd-svm .
#   docker run --rm --env-file .env -v "$PWD/data:/app/data" -v "$PWD/config:/app/config" bd-svm tick-idle
#
# Build with the UI check available:  docker build --build-arg WITH_UI=1 -t bd-svm .
FROM python:3.12-slim

ARG WITH_UI=0
WORKDIR /app

COPY requirements.txt requirements-ui.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$WITH_UI" = "1" ]; then \
         pip install --no-cache-dir -r requirements-ui.txt \
         && apt-get update && apt-get install -y --no-install-recommends chromium chromium-driver \
         && rm -rf /var/lib/apt/lists/*; \
       fi

COPY bd_svm ./bd_svm
COPY config ./config

RUN useradd --create-home runner && mkdir -p /app/data && chown -R runner /app
USER runner
VOLUME ["/app/data"]

ENTRYPOINT ["python", "-m", "bd_svm"]
CMD ["status"]
