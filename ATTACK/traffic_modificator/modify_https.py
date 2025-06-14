# To modify encrypted (HTTPS) traffic, you cannot use Scapy directly because HTTPS is encrypted at the transport layer. Instead, you need to use a 
# man-in-the-middle proxy like mitmproxy, which can decrypt, inspect, and modify HTTPS traffic.

# Here’s how you can do it with mitmproxy:
# 1. Install mitmproxy
# pip install mitmproxy

from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    # Example: Replace "Hello" with "Hi" in HTTPS responses
    if flow.response and b"Hello" in flow.response.content:
        flow.response.content = flow.response.content.replace(b"Hello", b"Hi")

# 3. Run mitmproxy with your script
# To run this script, save it as `modify_https.py` and run mitmproxy with the script:
# mitmproxy -s modify_https.py --mode transparent
# mitmproxy -s modify_https.py

# Note: You may need to set up mitmproxy as a transparent proxy and install its CA certificate in your browser or system to intercept HTTPS traffic.
# To modify HTTPS traffic, you can use mitmproxy, which allows you to intercept, inspect, and modify HTTP and HTTPS traffic.

# 4. Install mitmproxy’s certificate
# Install mitmproxy’s certificate Open your browser and go to http://mitm.it while mitmproxy is running.
# Download and install the certificate for your OS/browser.

# 5. Set your device/browser to use mitmproxy as the HTTPS proxy (Default: localhost:8080 or your chosen port.)
# Step-by-Step Guide
# Default Setup (localhost:8080)
# When you start mitmproxy, by default it listens on:
# Host: localhost
# Port: 8080
# You can change the port with:
# mitmproxy --listen-port 8888
# 🔧 1. Set the Proxy on Your Device or Browser
# A. On Your Browser (easiest)
# 🔹 Google Chrome / Firefox (desktop):
# Use your system’s proxy settings:
# On Windows:
# Go to Settings → Network & Internet → Proxy.
# Enable Manual proxy setup.
# Set:
# HTTP proxy: localhost
# Port: 8080
# Check “Use the same proxy server for all protocols”.