# SOC Threat Incident Framework: Deployment Guide

This guide details instructions for deploying the SOC threat analytics platform to production server environments using Docker Compose, configuring relational database persistent storage, and setting up system telemetry.

---

## 🐳 Dockerized Production Deployment

The framework is orchestrate with a multi-container architecture isolating the front-end dashboard, REST APIs, and database components:

### 1. Build and Launch Containers
To build the Docker images and run all services in detached (background) mode:
```bash
docker-compose up -d --build
```
This command automatically:
1. Pulls the PostgreSQL base image and boots the `soc_postgres_db` server.
2. Compiles the `Dockerfile` image containing python dependencies and packages.
3. Spawns `soc_api_service` serving Django on port `8000`.
4. Spawns `soc_dashboard_service` serving Streamlit on port `8501`.

---

## 💾 Relational Database Administration

The PostgreSQL instance is backed by a persistent Docker volume `pg_data` to ensure data persists across container shutdowns.

### 1. Database Backup (pg_dump)
Execute the backup command to export database schemas and tables:
```bash
docker exec -t soc_postgres_db pg_dump -U postgres -d soc_db > backup_soc_db.sql
```

### 2. Database Restore
To restore database states from a backup SQL file:
```bash
docker exec -i soc_postgres_db psql -U postgres -d soc_db < backup_soc_db.sql
```

---

## 📊 Telemetry and Operations Monitoring

### 1. Diagnostic Health Check
Django REST Framework exposes a public `/api/health/` JSON endpoint checking service vitals. You can query it using curl:
```bash
curl http://localhost:8000/api/health/
```
**Healthy Response Profile (`200 OK`)**:
```json
{
  "status": "Healthy",
  "database_connected": true,
  "model_loaded": true,
  "champion_model_name": "Gradient Boosting",
  "champion_model_f1": 0.9063
}
```

### 2. Logs Management
All services write logs to the shared `logs/` directory volume mapping:
- `logs/app.log`: General application and MLOps events.
- `logs/error.log`: Exception reports.
- `logs/api.log`: Django endpoint access telemetry logs.
- `logs/auth.log`: Authentication logins and RBAC access validation failures.
- `logs/db.log`: SQLite/PostgreSQL connection pool events.
