# SANS: Workshop: Offensive AI In Practice: Hands on Exploitation of Vulnerable Applications Using Open Source AI Tools
## April 2026

## Directory Map

After setup is complete, your project should look like this:

```
sans-ai-workshop-april-2026/
├── README.md                          <-- You are here
└── workshop-bundle/
    ├── .env                           <-- Your API keys (copy from .env.example)
    ├── .env.example
    ├── docker-compose.yml             <-- Defines all services (run from here)
    │
    ├── tools/                         <-- Cloned tool repositories go here
    │   ├── shannon/                   <-- git clone https://github.com/KeygraphHQ/shannon
    │   │   ├── Dockerfile             <-- Must exist (used by docker compose build)
    │   │   ├── apps/                  <-- Shannon source code
    │   │   ├── configs/               <-- Pentest config files (e.g., juice-shop.yaml)
    │   │   └── ...
    │   └── PentestGPT/                <-- git clone https://github.com/greydgl/pentestgpt
    │       ├── Dockerfile             <-- Must exist (used by docker compose build)
    │       └── ...
    │
    ├── workspace/                     <-- Shared working directory (mounted into containers)
    │   └── juice-shop/                <-- Target repo for Shannon findings
    │       └── .shannon/deliverables/ <-- Security reports land here
    │
    └── out/                           <-- Tool output / reports
        ├── zap/                       <-- ZAP scan reports (e.g., zap_baseline_report.html)
        └── shannon/                   <-- Shannon audit logs and session data
```

### Key Points

- **All `docker compose` commands must be run from `workshop-bundle/`** -- that's where `docker-compose.yml` lives.
- The `tools/` directory must contain **full git clones** of Shannon and PentestGPT (not just empty folders). Docker Compose needs each repo's `Dockerfile` to build the worker containers.
- The `workspace/` directory is mounted into both Shannon and PentestGPT containers, so findings persist on your host machine.
- The `out/` directory collects reports from ZAP and Shannon.

---

## Prerequisites

- Clone this repository
```bash
git clone 
```
- Install Docker and Docker Compose. This can be found at: https://www.docker.com/products/docker-desktop/
- Anthropic API key available from: https://platform.claude.com/
- Shannon should be installed into `workshop-bundle/tools/shannon/` - clone the repository at: https://github.com/KeygraphHQ/shannon
- PentestGPT should be installed into `workshop-bundle/tools/PentestGPT` - clone the repository at: https://github.com/greydgl/pentestgpt
- After cloning this repository creater a new folder called `tools/` in the `workshop-bundle` directory

```bash
#From within /sans-offensive-ai-in-practice-april-2026/workshop-bundle
git clone https://github.com/KeygraphHQ/shannon tools/shannon
git clone https://github.com/greydgl/pentestgpt tools/PentestGPT
```
## Initial Setup

1. Set up your API key:
```bash
cd workshop-bundle
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

2. Start all services:
```bash
docker compose up -d
```

This will start:
- **Juice Shop** - http://localhost:3000 (vulnerable web app)
- **zap-baseline** - Zap tooling
- **pentestgpt** - PenTestGPT tooling
- **Shannon Temporal** - (you can validate via: nc -vz localhost 7233)  (workflow engine)
- **Shannon Temporal UI** - http://localhost:8233 (monitoring dashboard)
- **Shannon Worker** - AI pentest agent
- **PostgreSQL** - Database for Temporal

## Run ZAP baseline (creates HTML report)

```bash
docker compose run --rm zap-baseline
# report at: ./out/zap/zap_baseline_report.html
```
This scan will take about five minutes to complete.
ZAP baseline scan scripts are included in the official ZAP images

## Run Shannon

Shannon is already included in `tools/shannon/`. Services should already be running from the Initial Setup step above.

### Verify Services are Running

Check that all services are healthy:
```bash
docker compose ps
```

You should see:
- `juice-shop` - STATUS: Up (healthy)
- `shannon-postgres` - STATUS: Up (healthy)
- `shannon-temporal` - STATUS: Up (healthy)
- `shannon-temporal-ui` - STATUS: Up

### Prepare a Target Repository

Shannon requires a git repository to store findings:

```bash
#From inside sans-offensive-ai-in-practice-april-2026/workshop-bundle run the following
mkdir -p workspace/juice-shop
cd workspace/juice-shop
git init
git config user.email "pentest@localhost"
git config user.name "Pentest Agent"
echo "# Juice Shop Pentest" > README.md
git add . && git commit -m "Initial commit"
cd ../..
```

### Create a Configuration File (Optional)

Create a config in `tools/shannon/configs/juice-shop.yaml`:

```yaml
# Juice Shop pentest configuration
rules:
  focus:
    - description: "Focus on API endpoints"
      type: path
      url_path: "/api/*"
    - description: "Focus on REST endpoints"
      type: path
      url_path: "/rest/*"
```

### Start the Pentest

Run the pentest workflow:

```bash
docker compose run --rm shannon-worker node apps/worker/dist/temporal/worker.js \
  http://juice-shop:3000 \
  /app/repos/juice-shop \
  --task-queue shannon
```

### Monitor Progress

**Temporal Web UI** (Recommended): http://localhost:8233
- View real-time workflow execution
- See activity history and task queues
- Monitor workflow state

**Worker Logs**:
```bash
docker compose logs -f shannon-worker
```

**Query Workflow Status**:
```bash
docker compose exec shannon-worker node apps/worker/dist/temporal/query.js <workflow-id>
```

### Results

Findings will be written to:
- `workshop-bundle/workspace/juice-shop/.shannon/deliverables` - Security findings and reports
- `out/shannon/` - Audit logs and session data

The pentest runs through 5 phases:
1. **Pre-Recon** - External scans + code analysis
2. **Recon** - Attack surface mapping
3. **Vulnerability Analysis** - 5 parallel agents (injection, xss, auth, authz, ssrf)
4. **Exploitation** - Exploit confirmed vulnerabilities
5. **Reporting** - Executive security report

## Run PentestGPT (Interactive)

PentestGPT is already included in `tools/PentestGPT/`. The container starts automatically with `docker compose up -d`.

### Connect to PentestGPT

Connect to the container interactively:

```bash
docker compose exec -it pentestgpt bash
```

You'll be in the `/workspace` directory where you can start pentesting.

### Run Against Juice Shop

Point it at Juice Shop:

```bash
pentestgpt --target juice-shop:3000
```

Or with specific instructions:

```bash
pentestgpt --target juice-shop:3000 --instruction "Focus on authentication bypass vulnerabilities"
```

### Common Options

```bash
pentestgpt --target juice-shop:3000              # Interactive TUI mode
pentestgpt --target juice-shop:3000 -n           # Non-interactive mode
pentestgpt --target juice-shop:3000 -v           # Verbose output
pentestgpt --list-sessions                       # List previous sessions
pentestgpt --resume --session-id <id>            # Resume a session
```

PentestGPT will guide you through an interactive penetration testing session with a TUI interface.

### If You Get "ENOENT: no such file or directory, uv_cwd" Error

If you encounter this error, the container needs to be recreated:

```bash
docker compose up -d pentestgpt
```

## Troubleshooting

### Shannon Temporal Not Starting

If you see "dependency failed to start: container shannon-temporal exited (1)", check the logs:

```bash
docker compose logs shannon-temporal
```

Common fixes:
- Ensure PostgreSQL is healthy: `docker compose ps shannon-postgres`
- Restart services: `docker compose restart shannon-temporal`

### Port Already in Use

If port 7233 or 8233 is already allocated:
```bash
# Stop all services
docker compose down

# Remove conflicting containers
docker ps -a | grep temporal
docker rm -f <container-id>

# Start services again
docker compose up -d
```

### Viewing Logs

View logs for any service:
```bash
docker compose logs -f <service-name>

# Examples:
docker compose logs -f shannon-worker
docker compose logs -f shannon-temporal
docker compose logs -f juice-shop
```

### Reset Everything

To start fresh:
```bash
cd workshop-bundle
docker compose down -v  # Remove volumes
docker compose up -d    # Start fresh
```


