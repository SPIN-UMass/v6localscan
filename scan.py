from scapy.all import *
from netaddr import *
from internal.scanner import Scanner, Requester, State
from flask import Flask, send_from_directory
import flask
import logging
import webbrowser


log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

state = State()

app = Flask(__name__, static_folder='./client-build')

# Serve React App
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

@app.route('/data')
def index():
    response = flask.jsonify(state.mac_to_deets)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response


def open_browser(url):
    try:
        try:
            webbrowser.get('chrome').open(url, new=2)
        except webbrowser.Error:
            webbrowser.open(url, new=2)
    except Exception:
        pass

if __name__ == '__main__':

    is_admin = os.getuid() == 0

    if not is_admin:
        sys.stderr.write('Please run as root \n')
        sys.exit(1)

    scanner = Scanner(state)
    scanner.start() 
    
    requester = Requester()
    requester.start()

    open_browser('http://localhost:7279')
    app.run(port=7279, threaded=True, debug=False)