FROM python:3.14.6-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENV KEYSCOPE_HOST=0.0.0.0 PORT=8000
WORKDIR /app
COPY --chown=10001:10001 app.py index.html dashboard.html app.js policy.mjs style.css keyscope-hero.webp threat-feed.json ./
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=3s --start-period=5s --retries=3 CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.getenv('PORT','8000'), timeout=2)"]
CMD ["python", "app.py"]
