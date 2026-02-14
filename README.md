# API Load & Stress Tester

Hoppscotch-style API tool with **load testing**, **stress testing**, and **regression** runs. Uses your `hoppscotch-team-collections.json` file.

## Features

- **Single API**: Run one API multiple times (iterations + concurrency) for load/stress
- **Multiple APIs**: Select several APIs and run them together
- **Regression**: Run all APIs in the collection (full regression)
- **Reports**: Summary + per-API stats (success/fail, latency avg/p95/p99, throughput)
- **Charts**: Latency distribution
- **Export**: Download report as JSON

## Quick start

```bash
npm install
npm start
```

Open **http://localhost:3847**

## Usage

1. **Base URL**: Set the base URL (replaces `<<baseUrl>>` in your endpoints).
2. **Mode**:
   - **Single API**: Select one request in the sidebar, set iterations and concurrency, then Run.
   - **Multiple APIs**: Select multiple (checkboxes), then Run.
   - **Regression**: Run all APIs (no selection needed).
3. **Iterations**: How many times each selected API is called per run.
4. **Concurrency**: How many requests run in parallel (higher = more load/stress).
5. **Run test**: Starts the run and shows summary + per-request stats and chart.
6. **Export report**: Downloads the last run as a JSON report.

## Collection file

Keep `hoppscotch-team-collections.json` in the same folder as `server.js`. The app reads it on load and for each run. Endpoints can use `<<baseUrl>>` and request variables like `<<id>>`; set Base URL in the UI and variables in your request definition.

## Deploy on Vercel

1. Push this repo to GitHub (or connect your Git provider in Vercel).
2. In [Vercel](https://vercel.com): **New Project** → Import this repo.
3. Leave **Build Command** and **Output Directory** as default (no build step).
4. Deploy. Your app will run at `https://your-project.vercel.app`.

**Note:** On Vercel, collections are stored in temporary storage. After deploy, use **Import** in the app to upload your `hoppscotch-team-collections.json`. Data may reset on cold starts; for persistent data use local run or a database.

## Tech

- **Backend**: Node.js + Express (runs requests, avoids CORS)
- **Frontend**: Vanilla JS + Chart.js
- **Format**: Hoppscotch team collections JSON
