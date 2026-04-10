# Network Operation Defender (HITL)

# Description: Safely process IP blockes for human review.

## Tool: stage_ip_block 
Use this tools when you detect a severe network anomaly. you MUST NOT attach to run shell commands. You must use this tools to stage a rule for human approval.

### parameter
- `ip_address`(string, required): The exact IPv4 address to block

### Execution:
command: python stage_ip_block.py {ip_address}

### Response:
- If the tool returns "success", you can confirm the action to the user.
- If the tool returns an error, you must inform the user and ask for clarification.
