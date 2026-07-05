import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from warehouse_os.app import create_app
create_app().run(host="0.0.0.0", port=5002, debug=False)
