FROM --platform=$BUILDPLATFORM python:3.11-slim as builder

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir flask routeros_api

FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /app /app

EXPOSE 5000
CMD ["python", "app.py"]
