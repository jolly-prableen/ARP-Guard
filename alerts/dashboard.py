# alerts/dashboard.py
from flask import Flask, render_template

app = Flask(__name__)

# Sample mock data for standalone testing (will link with Person A's engine later)
trusted_devices = {
    "192.168.1.1": "AA:BB:CC:DD:EE:FF",  # Router
    "192.168.1.15": "11:22:33:44:55:66" # Victim VM
}

alert_history = [
    "2026-10-17 23:15:00 - WARNING: IP 192.168.1.15 MAC changed unexpectedly!"
]

@app.route('/')
def index():
    return render_template('index.html', devices=trusted_devices, alerts=alert_history)

if __name__ == '__main__':
    app.run(debug=True, port=5000)