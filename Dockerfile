# Use official light Python image
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Install system dependencies (including package managers for network lookups)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file first to utilize Docker build cache
COPY requirements.txt /app/

# Install Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . /app/

# Expose Flask default port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=app.py
ENV DEBUG=False
ENV PORT=5000

# Run model training first to generate models/phishing_model.pkl, then start Flask app
CMD python ml/train.py && python app.py
