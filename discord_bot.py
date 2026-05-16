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
    """
    Usage: !approve 192.168.1.1
    Acts exactly like the Web Dashboard, telling the FastAPI server to delegate the execution command to OpenClaw.
    """
    await ctx.send(f"🛡️ Relaying authorization to OpenClaw to block `{ip_address}`...")
    
    try:
        # We hit our existing FastAPI endpoint just like the Web Dashboard does!
        response = requests.post(
            FASTAPI_URL, 
            json={"ip_address": ip_address},
            timeout=15
        )
        
        if response.status_code == 200:
            # We don't need to say success here, because OpenClaw will send a Webhook confirming it!
            pass
        else:
            await ctx.send(f"❌ Backend rejected the command: {response.text}")
            
    except requests.exceptions.RequestException as e:
        await ctx.send(f"❌ Failed to reach the FastAPI server. Is it running? Error: {e}")

if __name__ == "__main__":
    # You will need to install the discord library: pip install discord.py
    
    # --- PASTE YOUR SECRET BOT TOKEN BELOW ---
    DISCORD_BOT_TOKEN = os.getenv("DISCORD_TOKEN")
    
    if DISCORD_BOT_TOKEN == None:
        print("ERROR: Please paste your Bot Token into discord_bot.py!")
    else:
        bot.run(DISCORD_BOT_TOKEN)