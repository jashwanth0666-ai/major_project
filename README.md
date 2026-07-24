# AI-Driven Phishing Website Detection System

A hybrid, industry-style final year project to detect phishing websites in real time using **Java + Python + React**.

## 📌 Project Overview

This system analyzes suspicious URLs and predicts whether a website is **Phishing** or **Legitimate** by combining secure backend services and ML inference.

- **Spring Boot (Java)** handles authentication, business logic, API orchestration, and data management.
- **Python FastAPI** service handles feature extraction and machine learning prediction.
- **React + TypeScript + Tailwind CSS** provides an interactive dashboard for scans, reports, and analytics.

The architecture is designed for collaboration, scalability, and production-like engineering practices.

---

## 🎯 Goals

- Detect phishing websites with high accuracy.
- Provide low-latency prediction APIs for real-time checks.
- Maintain modular services that can scale independently.
- Follow industry workflow: branching strategy, PR reviews, CI checks.

---

## 🧱 Technology Stack

### Frontend
- React.js
- TypeScript
- Tailwind CSS

### Backend
- Spring Boot (Java)
- Spring Security + JWT

### AI/ML Service
- Python
- FastAPI
- Scikit-learn / XGBoost / LightGBM
- (Optional) TensorFlow / Keras

### Data & Messaging
- PostgreSQL
- Redis
- RabbitMQ

### Integrations
- VirusTotal API
- Google Safe Browsing API

### DevOps / Infra
- Docker
- Nginx
- GitHub Actions (CI/CD)
- AWS / Azure (future deployment)

### Observability (future scope)
- Prometheus + Grafana
- ELK Stack (Elasticsearch, Logstash, Kibana)

---

## 🏗️ High-Level Architecture

1. User submits URL from the React dashboard.
2. Spring Boot API validates request, authenticates user, and orchestrates processing.
3. Spring Boot sends URL/job to Python FastAPI service (direct call or via queue).
4. Python service performs:
   - URL/HTML/DNS/WHOIS/SSL feature extraction
   - ML inference (phishing vs legitimate)
5. Result is returned to Spring Boot.
6. Spring Boot stores scan history in PostgreSQL, caches hot data in Redis, and returns response to frontend.
7. Frontend renders result, confidence, and analytics/report views.

---

## 🔐 Security Principles

- JWT-based authentication and role-based authorization.
- HTTPS-only communication in deployment.
- Input validation and sanitization for all APIs.
- Secret/config separation using environment variables.

---

## 👥 Team Collaboration Model

Recommended for 4 members:

- **Member 1:** Spring Boot API + auth + integration lead
- **Member 2:** React dashboard + UX + charts
- **Member 3:** Python FastAPI + ML training/inference
- **Member 4:** DevOps + Docker + CI/CD + monitoring

Use issue-based work allocation and PR reviews for each feature.

---

## 🌿 Branching Strategy

- `main` → stable, release-ready code
- `develop` → integration/testing branch
- `feature/*` → individual tasks

Examples:
- `feature/react-dashboard`
- `feature/spring-auth-jwt`
- `feature/fastapi-ml-predict`
- `feature/docker-compose-setup`

---

## ✅ Definition of Done (DoD)

A task is complete when:

- Code is pushed to a feature branch.
- PR is created with clear description.
- At least one teammate review is completed.
- CI checks pass.
- Feature is tested locally.
- Documentation is updated if needed.

---

## 🚀 Initial Milestones

1. Repository bootstrap: docs, branch rules, templates.
2. Backend auth + basic URL scan API.
3. Python ML microservice with baseline model.
4. Frontend dashboard integration.
5. Queue/caching integration and optimization.
6. CI/CD pipeline and deployment draft.

---

## 📄 License

To be decided by team (recommended: MIT for academic collaboration).
