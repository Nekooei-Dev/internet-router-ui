
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install flask routeros-api
EXPOSE 5000
CMD ["python", "app.py"]
