FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY apps/api/pyproject.toml /app/pyproject.toml
COPY apps/api/src /app/src
RUN pip install --no-cache-dir -e .
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app

EXPOSE 8000
USER appuser
CMD ["uvicorn", "hallu_defense.main:app", "--host", "0.0.0.0", "--port", "8000"]
