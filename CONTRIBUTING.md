# Contributing to SOC Analytics Framework

Thank you for choosing to contribute to our Security Operations Center (SOC) Analytics Platform! Please follow these guidelines to keep our repository clean, secure, and production-quality.

---

## 💻 Workflow & Branches
1. Fork this repository and create your feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Commit your changes using descriptive logs.
3. Push to the branch:
   ```bash
   git push origin feature/your-feature-name
   ```
4. Create a Pull Request (PR) targeting the `main` branch.

---

## 🎨 Code Style and Standards
- **Style**: Follow PEP 8 guidelines.
- **Typing**: Use static Python type hints for all parameters and function return values.
- **Documentation**: All classes, methods, and functions must contain detailed docstrings.
- **Dependencies**: Keep your added modules dependency-free when possible, or update `requirements.txt` with locked versions.

---

## 🧪 Testing & CI Checks
All contributions must pass the local test suite prior to review. Run tests using:
```bash
python -m pytest --cov=src --cov=api --cov=mlops tests/
```
Ensure code coverage does not fall below the project target of **80%** for new code edits.
