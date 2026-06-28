FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Drop privileges.
RUN useradd --create-home --uid 10001 botuser
USER botuser

CMD ["python", "main.py"]
