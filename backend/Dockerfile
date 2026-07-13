FROM python:3.11-slim

# Install system dependencies including tshark and libmagic
RUN apt-get update && \
    apt-get install -y tshark libpcap-dev libmagic1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create uploads directory
RUN mkdir -p /app/uploads

# Copy the rest of the application
COPY . .

# Expose the port
EXPOSE 8000

# Run the FastAPI application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
