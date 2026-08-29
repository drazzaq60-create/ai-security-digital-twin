# hello.py — my first program that talks to an AI

import os                          # lets us read saved values (like our key)
from dotenv import load_dotenv     # the tool that opens our .env file
from groq import Groq              # Groq's official library

load_dotenv()                      # 1) load the secrets from .env

# 2) create our connection to Groq, using the secret key
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# 3) send a message to the AI and get its reply
response = client.chat.completions.create(
    model="llama-3.1-8b-instant",
    messages=[
        {"role": "user", "content": "Say a short, encouraging hello to Danish, who just wrote his very first program that talks to an AI."}
    ],
)

# 4) print just the AI's answer
print(response.choices[0].message.content)