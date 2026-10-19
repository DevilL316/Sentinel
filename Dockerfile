FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -r sentinel && chown -R sentinel /app
USER sentinel
ENV SENTINEL_DB=/app/data/sentinel.db
RUN mkdir -p /app/data
EXPOSE 8000
CMD ["uvicorn", "sentinel.app:app", "--host", "0.0.0.0", "--port", "8000"]
