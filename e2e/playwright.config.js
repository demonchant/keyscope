import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 45_000,
  expect: { timeout: 30_000 },
  reporter: [['list'], ['html', { outputFolder: 'artifacts/report', open: 'never' }]],
  use: {
    baseURL: process.env.BASE_URL || 'http://127.0.0.1:8000',
    browserName: 'chromium',
    httpCredentials: process.env.KEYSCOPE_ACCESS_PASSWORD ? { username: 'keyscope', password: process.env.KEYSCOPE_ACCESS_PASSWORD } : undefined,
    headless: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    reducedMotion: 'reduce'
  },
  outputDir: 'artifacts/results'
});
