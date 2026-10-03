FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml /app/
RUN pip install --upgrade pip && pip install .
COPY . /app
ENV CTI_CONNECTORS=/config/connectors.yaml
ENV PYTHONUNBUFFERED=1
CMD ["cassandra", "run", "--config", "/config/config.yaml"]


