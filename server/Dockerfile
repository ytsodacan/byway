FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV BYWAY_HOME=/data BYWAY_DASH_HOST=0.0.0.0
VOLUME ["/data", "/root/.mitmproxy"]
EXPOSE 8080 8081
ENTRYPOINT ["/app/entrypoint.sh"]
