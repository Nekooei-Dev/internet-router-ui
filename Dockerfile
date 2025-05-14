FROM python:3.11-alpine
WORKDIR /app
COPY backend/ .
RUN pip install flask librouteros flask_httpauth
CMD ["python", "app.py"]
