import sys
sys.path.insert(0, "C:/Users/abhir/OneDrive/Desktop/proj")
from warehouse_os.app import create_app
create_app().run(host="0.0.0.0", port=5002, debug=False)
