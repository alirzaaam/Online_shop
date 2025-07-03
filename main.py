import os
from flask import Flask, redirect, request, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Float
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
import stripe



stripe.api_key = os.environ.get("API_KEY")
YOUR_DOMAIN = 'http://localhost:4242'

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")



class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
# db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(Database, user_id)


class Database(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(250), nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)

with app.app_context():
    db.create_all()



@app.route('/')
def index():
    all_products = stripe.Product.list(limit=20)
    data = all_products['data']
    user_name = current_user.username if current_user.is_authenticated else None

    return render_template('index.html', data=data, logged_in=current_user.is_authenticated, user=user_name)

@app.route('/login', methods=['POST', 'GET'])
def login():
    
    if request.method == 'POST':
        get_email = request.form.get('email')
        get_pass = request.form.get('pass')
        result = db.session.execute(db.select(Database).where(Database.email == get_email)).scalar()
        if check_password_hash(result.password, get_pass) and  result.email == get_email:
            print(result.username)
            login_user(result)
            return redirect(url_for('index'))
        else:
            return redirect(url_for('login'), logged_in=current_user.is_authenticated, user=current_user.name)
         
    else:
        return render_template('login.html')
    
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        get_email = request.form.get('email')
        get_user = request.form.get('username')
        get_pass = request.form.get('pass')
        get_repass = request.form.get('repass')
        if get_pass == get_repass:
            new_user = Database(email=get_email, username=get_user, password=generate_password_hash(get_pass, method='scrypt', salt_length=16))
            db.session.add(new_user)
            db.session.commit()

            load_user(new_user)

            return redirect(url_for('index'))
        else:
            return redirect('/register')

    else:
        return render_template('register.html', logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))



@app.route('/create-checkout-session/<price_id>', methods=['POST'])
def create_checkout_session(price_id):
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    # Provide the exact Price ID (for example, price_1234) of the product you want to sell
                    'price': price_id,
                    'quantity': 1,
                },
            ],
            mode='payment',
            success_url=YOUR_DOMAIN + '/success.html',
            cancel_url=YOUR_DOMAIN + '/cancel.html',
        )
    except Exception as e:
        return str(e)

    return redirect(checkout_session.url, code=303)

if __name__ == '__main__':
    app.run(port=4242, debug=True)

