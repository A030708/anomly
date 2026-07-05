import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from boltmart.app import create_app
app = create_app()
print("BoltMart started", flush=True)
app.run(host="0.0.0.0", port=5001, debug=True)
