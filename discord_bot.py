import os
from dotenv import load_dotenv
load_dotenv()
import discord
from discord.ext import commands
import requests

# Setup the Discord Bot with intent to read messages
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# The URL of your FastAPI server
FASTAPI_URL = "http://127.0.0.1:8000/approve-block"

@bot.event
async def on_ready():
    print(f'✅ ChatOps Bot logged in as {bot.user}')
    print('Listening for !approve commands in Discord...')

@bot.command()
async def approve(ctx, ip_address: str):
    """Listens for !approve 192.168.1.1 in Discord"""
    await ctx.send(f"🛡️ Relaying authorization to block `{ip_address}`...")

    try:
        response = requests.post(
            FASTAPI_URL,
            json={"ip_address": ip_address},
            timeout=15
        )

        if response.status_code == 200:
            await ctx.send(f"✅ **Success!** OpenClaw confirmed the block on `{ip_address}`.")

        elif response.status_code == 409:
            # Guardrail: IP is already blocked — not an error, just inform the user
            await ctx.send(f"ℹ️ `{ip_address}` is **already blocked**. No action needed.")

        elif response.status_code == 422:
            # Guardrail: IP failed validation (malformed, loopback, etc.)
            detail = response.json().get("detail", response.text)
            await ctx.send(f"⚠️ **Invalid IP address:** {detail}")

        else:
            await ctx.send(f"❌ Unexpected response from backend (HTTP {response.status_code}): {response.text}")

    except requests.exceptions.RequestException as e:
        await ctx.send(f"❌ Failed to reach the FastAPI server. Is Uvicorn running? Error: {e}")

if __name__ == "__main__":
    # --- PASTE YOUR SECRET BOT TOKEN BELOW ---
    DISCORD_BOT_TOKEN = os.getenv("DISCORD_TOKEN")
    
    if DISCORD_BOT_TOKEN is None:
        print("ERROR: DISCORD_TOKEN environment variable is not set!")
        print("Please set it in your terminal before running this script.")
    else:
        print("DISCORD_TOKEN found.")
        bot.run(DISCORD_BOT_TOKEN)