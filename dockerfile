FROM python:3.9-slim

# Set environment variables (using the correct format)
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Set the working directory
WORKDIR /app

# Install necessary system dependencies
RUN apt-get update && \
    apt-get install -y python3-tk pkg-config gcc libmariadb-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Command to run the application (replace with your command)
CMD ["python", "app.py"]
