FROM mcr.microsoft.com/playwright:v1.64.1-noble
WORKDIR /tests
COPY package.json package-lock.json ./
RUN npm ci
COPY playwright.config.js ./
COPY tests ./tests
RUN mkdir -p /tests/artifacts && chown -R pwuser:pwuser /tests
USER pwuser
CMD ["npx", "playwright", "test"]
