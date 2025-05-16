FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc libffi-dev libssl-dev build-essential && apt-get clean

COPY requirements.txt ./
RUN pip install --upgrade pip --quiet
RUN pip install --no-cache-dir -r requirements.txt --quiet

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
