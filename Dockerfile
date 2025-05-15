FROM python:3.10-slim

WORKDIR /app

COPY . /app

RUN pip install flask routeros-api python-dotenv

EXPOSE 80

CMD ["python", "app.py"]
