# Use an official lightweight Python image
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies needed for compiling python extensions (like lightgbm/catboost)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first to leverage Docker cache layers
COPY requirements.txt /app/

# Install python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire workspace into the container
COPY . /app/

# Create folders for data, models, and logs if not present
RUN mkdir -p data/raw data/processed models/registry logs alerts

# Default ports exposed (FastAPI: 8000, Streamlit: 8501)
EXPOSE 8000 8501

# Command to be overridden by docker-compose or run arguments
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
