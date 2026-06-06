# Autonomous Enterprise Code Review & Security Audit Agent System

A production-grade, multi-agent system that automatically reviews GitHub Pull Requests at scale using LangGraph orchestration, specialized security/compliance agents, and a full observability stack.

## Architecture Overview

```
GitHub Webhook → FastAPI → Kafka → Celery Workers
                                        ↓
                              LangGraph Orchestrator
                             /    |     |     |     \
                    Static  Sec  Dep  Comp  Remedia Reflect
                    Analysis Audit Check iance  tion    ion
                             \    |     |     |     /
                              Synthesize → Report
                                   ↓
                        PostgreSQL + Weaviate + Redis
                                   ↓
                          React Dashboard (SSE streaming)
```

## Features

- **Multi-Agent Orchestration**: LangGraph-based orchestrator spawning specialized agents
- **Security Audit**: OWASP Top 10 coverage, secret scanning, injection vector detection
- **Static Analysis**: Semgrep integration, AST-based analysis, cyclomatic complexity
- **Dependency Analysis**: CVE database integration (OSV.dev), license compatibility
- **Compliance**: GDPR, SOC2 control mapping, audit logging checks
- **Remediation**: Auto-generated patches and fix suggestions
- **Reflection**: GPT-4o-as-judge meta-evaluation with false positive detection
- **Scale**: Handles 500+ PRs/day with async Celery workers
- **Observability**: OpenTelemetry tracing, Prometheus metrics, Grafana dashboards

## Tech Stack

### Backend
- **FastAPI** + **Uvicorn** - Async HTTP server
- **Celery** + **Redis** - Distributed task queue
- **LangGraph** - Agent orchestration
- **LangChain** + **Anthropic/OpenAI** - LLM integration
- **PostgreSQL** + **SQLAlchemy** - Relational data
- **Weaviate** - Vector store for code RAG
- **Kafka** - Event streaming

### Frontend
- **React 18** + **TypeScript** + **Vite**
- **TanStack Query** - Data fetching
- **Recharts** - Visualizations
- **Radix UI** + **Tailwind CSS** - UI components

### Infrastructure
- **Kubernetes** (GKE) - Container orchestration
- **Terraform** - Infrastructure as Code
- **Helm** - Kubernetes package management
- **GitHub Actions** - CI/CD

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Node.js 18+
- GitHub App configured

### 1. Clone and Configure

```bash
git clone <repo-url>
cd autonomous-enterprise-code-review-and-security-audit-agent-system
cp .env.example .env
# Edit .env with your API keys
```

### 2. Start Local Stack

```bash
make dev
```

This starts:
- FastAPI backend on http://localhost:8000
- React dashboard on http://localhost:3000
- PostgreSQL on port 5432
- Redis on port 6379
- Kafka on port 9092
- Weaviate on port 8080

### 3. Run Migrations

```bash
make migrate
```

### 4. Configure GitHub Webhook

1. Create a GitHub App at https://github.com/settings/apps
2. Set webhook URL to `https://your-domain.com/webhooks/github`
3. Subscribe to `pull_request` events
4. Add credentials to `.env`

## Development

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Format code
make format

# Lint
make lint

# Start Celery worker
make worker

# Start Kafka consumer
make consumer
```

## API Documentation

When running locally, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/webhooks/github` | GitHub webhook receiver |
| GET | `/prs/` | List all PRs |
| GET | `/prs/{id}` | Get PR details |
| POST | `/prs/{id}/trigger-review` | Manually trigger review |
| GET | `/prs/{id}/findings` | Get PR findings |
| GET | `/findings/` | List all findings |
| POST | `/findings/{id}/feedback` | Submit human feedback |
| GET | `/metrics/summary` | Dashboard metrics |
| GET | `/agents/runs/` | List agent runs |

## Agent System

### Orchestrator

The LangGraph orchestrator routes PRs through agents based on risk score:

- **Low risk (< 0.3)**: Static analysis only
- **Medium risk (0.3-0.7)**: + Security audit + Dependency check
- **High risk (> 0.7)**: All agents including Compliance and deep Remediation

### Agents

| Agent | Purpose | Tools |
|-------|---------|-------|
| `StaticAnalysisAgent` | Code quality | Semgrep, AST, complexity |
| `SecurityAuditAgent` | Security vulns | OWASP, secret scan, injection |
| `DependencyAgent` | Dep vulnerabilities | OSV.dev, license check |
| `ComplianceAgent` | Regulatory compliance | GDPR, SOC2 |
| `RemediationAgent` | Fix suggestions | Patch generation, alternatives |
| `ReflectionAgent` | Quality control | GPT-4o judge, confidence scoring |

## Production Deployment

### GKE Deployment

```bash
# Initialize Terraform
cd infra/terraform
terraform init
terraform plan
terraform apply

# Deploy to Kubernetes
make k8s-deploy
```

### Helm Deployment

```bash
helm upgrade --install code-review infra/helm \
  -f infra/helm/values.prod.yaml \
  --set global.image.tag=$(git rev-parse --short HEAD)
```

## Observability

- **Traces**: OpenTelemetry → OTLP → Jaeger
- **Metrics**: Prometheus → Grafana (dashboard JSON in `observability/`)
- **Logs**: structlog → stdout → Loki
- **Alerts**: Prometheus rules in `observability/alerts.yaml`

## Configuration

All configuration is via environment variables. See `.env.example` for full documentation.

Key settings:

```bash
RISK_SCORE_THRESHOLD=0.7      # Threshold for high-risk routing
MAX_AGENT_STEPS=10            # Max LangGraph steps per agent
ANTHROPIC_API_KEY=sk-ant-...  # Claude API key
GITHUB_WEBHOOK_SECRET=...     # Webhook HMAC secret
```

## License

MIT License - see LICENSE file for details.
