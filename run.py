from app import create_app, db
from app.models import User
import os

app = create_app()

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}

if __name__ == '__main__':
    ssl_context = (
        'certs/cert.pem',
        'certs/key.pem'
    )
    app.run(debug=True, port=5003, ssl_context=ssl_context) 