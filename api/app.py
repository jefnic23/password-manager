from api.config import Config
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask import Flask

db = SQLAlchemy()
mail = Mail()
talisman = Talisman()

def create_app(config_class=Config):
    app = Flask(__name__, static_folder='../frontend/build', static_url_path='/')
    app.config.from_object(config_class)
    
    db.init_app(app)
    mail.init_app(app)
    talisman.init_app(app, content_security_policy=None)

    from api.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    # from api.main import bp as main_bp
    # app.register_blueprint(main_bp)

    @app.route('/')
    def index():
        return app.send_static_file('index.html')

    return app
