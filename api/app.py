from flask import Flask
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy

from api.config import Config

db = SQLAlchemy()
mail = Mail()


def create_app(config_class=Config):
    app = Flask(__name__, static_folder='../frontend/build', static_url_path='/')
    app.config.from_object(config_class)
    
    db.init_app(app)
    mail.init_app(app)

    from api.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/api')

    from api.main import bp as main_bp
    app.register_blueprint(main_bp, url_prefix='/api')

    @app.route('/')
    def index():
        return app.send_static_file('index.html')

    return app
