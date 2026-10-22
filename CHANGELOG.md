# Changelog

All notable changes to the SOC Threat Incident Analytics and Security Visualization Framework will be documented in this file.

---

## [2.1.0] - 2026-10-22
### Added
- **One-Click Windows Launchers**: Added `run_dashboard.bat`, `run_api.bat`, and `run_django.bat` for seamless local startup.
- **Windows UTF-8 Encoding Support**: Added explicit environment flags (`PYTHONUTF8=1`, `PYTHONIOENCODING=utf-8`) to prevent CLI unicode errors on Python 3.14.
- **Comprehensive Documentation**: Updated `README.md` with full system architecture, quick-start guides, and feature workflows.

### Fixed
- **Virtual Environment Path**: Updated `pyvenv.cfg` from legacy OneDrive path to local workspace directory.
- **JWT Deprecation**: Fixed deprecated `datetime.utcnow()` in `api/auth.py` by transitioning to timezone-aware UTC timestamps (`datetime.now(timezone.utc)`).
- **Test Timestamps**: Updated `tests/test_core.py` to use timezone-aware datetimes, eliminating Django ORM naive datetime warnings.

---

## [2.0.0] - 2026-08-04
### Added
- **Database schemas**: Dynamic support for SQLite, PostgreSQL, and MySQL using SQLAlchemy. Added tables for Users, Ingested incidents, predictions, and audit log histories.
- **FastAPI service**: Created REST endpoints secure by JWT (JSON Web Tokens) and Role-Based Access Control (RBAC).
- **MLOps sub-module**: Implemented version registries and real-time distribution drift tracking via the Population Stability Index (PSI) equations.
- **Explainable AI (XAI)**: Integrated local SHAP attributions into predictions response models.
- **Forecasting engine**: Programmed daily ARIMA models predicting alert counts with 95% confidence intervals.
- **Docker Compose**: Containerized application services linking databases and dashboards.
- **GitHub Actions CI**: Formulated testing workflows on branch pushes.

### Fixed
- Multiprocessing serialization errors on Windows machines by configuring sequential grid CV searches.
- Resolved password hashing failures under Python 3.14 by utilizing standard `sha256_crypt` schemes.

---

## [1.0.0] - 2026-08-03
### Added
- Initial release.
- Synthetic security incident generator seeding 12,000 logs.
- Data cleanings and baseline feature selections.
- Random Forest model training.
- Baseline Streamlit dashboard interface.
- CSV/PDF Report generation scripts.
