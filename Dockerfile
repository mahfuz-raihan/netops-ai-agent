# Use a lightweight Python image
FROM python:3.10-slim

# Create a non-root user named 'agentuser' for security
RUN useradd -m -s /bin/bash agentuser

# Set the working directory inside the container
WORKDIR /app

# Install OpenClaw and requests
RUN pip install --no-cache-dir openclaw requests

# Copy your custom netops skill into the container
COPY ./netops_skill /app/netops_skill

# Create the staging file for our Human-in-the-Loop firewall rules
RUN touch /app/staged_rules.txt

# Give 'agentuser' ownership of the app directory so it can write to the file
RUN chown -R agentuser:agentuser /app

# Switch from 'root' to our restricted user
USER agentuser

# Register the skill locally for the agentuser
RUN openclaw plugins install ./netops_skill

# Expose the port OpenClaw will run on
EXPOSE 8001

# Start the OpenClaw gateway server
CMD ["openclaw", "serve", "--host", "0.0.0.0", "--port", "8001"]