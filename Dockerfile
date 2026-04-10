# Use a lightweight Python image
FROM python:3.10-slim

# Create a non-root user for security
RUN useradd -m -s /bin/bash agentuser

WORKDIR /app

# Install dependencies for our custom agent server
RUN pip install --no-cache-dir fastapi uvicorn requests

# Copy our custom agent server and the skill folder into the container
COPY agent_server.py /app/agent_server.py
COPY ./netops_skill /app/netops_skill

# Create the staging file for our Human-in-the-Loop firewall rules
RUN touch /app/staged_rules.txt

# Give the restricted user ownership
RUN chown -R agentuser:agentuser /app

# Switch to the restricted user
USER agentuser

EXPOSE 8001

# Run our custom Agent Gateway instead of the CLI tool
CMD ["python", "agent_server.py"]