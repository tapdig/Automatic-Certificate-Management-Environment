from flask import Flask
import os
import signal

class ShutdownHttpServer:
    def __init__(self):
        self.server = Flask(__name__)

        @self.server.route('/shutdown', methods=['GET'])
        def shutdown():
            # os.kill(os.getpid(), signal.SIGINT)
            os.kill(os.getpid(), signal.SIGTERM)
            return "Server has been shut down."

    def start_server(self, host, port):
        self.server.run(host=host, port=port, threaded=True)