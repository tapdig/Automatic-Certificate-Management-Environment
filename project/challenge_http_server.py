from flask import Flask
import flask

class ChallengeHttpServer:
    def __init__(self):
        self.tokens = {"token": "token_value"}
        self.server = Flask(__name__)

        @self.server.route('/.well-known/acme-challenge/<string:token>', methods=['GET'])
        def http_challenge(token):
            if self.tokens.get(token) is not None:
                return flask.Response(self.tokens[token], content_type="application/octet-stream")
            flask.abort(404, "Token not in challenge list")


    def register_challenge(self, token, auth):
        self.tokens[token] = auth

    def start_server(self, host, port):
        self.server.run(host=host, port=port, threaded=True)