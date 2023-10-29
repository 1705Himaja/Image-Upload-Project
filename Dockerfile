FROM python:3.11.4

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

# ENV GOOGLE_APPLICATION_CREDENTIALS ./service-account-key.json

CMD ["python", "app.py"]
