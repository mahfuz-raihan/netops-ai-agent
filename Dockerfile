# Use a lightweight Python image
FROM python:3.10-slim

# Create a non-root user for security
RUN useradd -m -s /bin/bash agentuser

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir fastapi uvicorn requests openclaw

# Copy files
COPY agent_server.py /app/agent_server.py
COPY ./netops_skill /app/netops_skill

# Create BOTH files and give the restricted user permission to write to them
RUN touch /app/staged_rules.txt
RUN touch /app/firewall_rules.txt
RUN chown -R agentuser:agentuser /app

# Switch to the restricted user
USER agentuser

EXPOSE 8001

# Run our custom Agent Gateway
CMD ["python", "agent_server.py"]