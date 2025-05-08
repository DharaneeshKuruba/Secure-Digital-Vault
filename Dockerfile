FROM ubuntu:latest

# Install system dependencies: Python, pip, and tkinter (python3-tk)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-tk \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install them (override the externally-managed environment)
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy project files into the container
COPY . /app

# Run the script
CMD ["python3", "gui.py"]
