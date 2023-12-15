from flask import Flask, render_template, request, redirect, url_for, session, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Add more fields for order details as needed

CEO_USERNAME = 'ceo'
CEO_PASSWORD = 'Saif1234'

@app.route('/')
def home():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        orders = Order.query.filter_by(user_id=user.id).all()
        return render_template('dashboard.html', username=username, orders=orders)
    return redirect(url_for('login'))

@app.route('/track_order/<int:order_id>')
def track_order(order_id):
    # Implement logic to retrieve and display order details
    return render_template('track_order.html', order_id=order_id)

@app.route('/create_order', methods=['GET', 'POST'])
def create_order():
    if request.method == 'POST':
        # Extract order details from the form
        product = request.form['product']
        quantity = request.form['quantity']
        total_price = request.form['total']

        # Validate form data
        if not all([product, quantity, total_price]):
            return render_template('create_order.html', error='Please fill in all fields')

        try:
            # Convert quantity and total_price to appropriate types
            quantity = int(quantity)
            total_price = float(total_price)
        except ValueError:
            return render_template('create_order.html', error='Invalid quantity or total price')

        # Create a new order and associate it with the logged-in user
        if 'username' in session:
            username = session['username']
            user = User.query.filter_by(username=username).first()
            new_order = Order(product=product, quantity=quantity, total_price=total_price, user=user)

            # Save the order to the database
            db.session.add(new_order)
            db.session.commit()

            return redirect(url_for('home'))

    return render_template('create_order.html', error=None)

@app.route('/delete_order/<int:order_id>')
def delete_order(order_id):
    # Implement logic to delete the specified order
    # Redirect to the dashboard or order list page
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None  # Initialize error message

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == CEO_USERNAME and password == CEO_PASSWORD:
            session['username'] = username
            return redirect(url_for('ceo_home'))

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            error = 'Incorrect username or password'

    return render_template('login.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Password validation criteria
        password_regex = re.compile(r'^(?=.*[A-Z])(?=.*\d).{8,}$')

        if not password_regex.match(password):
            return render_template('signup.html', error='Password must include 8 characters with at least 1 upper case and 1 number')

        with current_app.app_context():
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                return render_template('signup.html', error='Username already exists!')

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login'))

    return render_template('signup.html', error=None)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# ... (previous code)

@app.route('/ceo_home')
def ceo_home():
    if 'username' in session and session['username'] == CEO_USERNAME:
        return render_template('ceo_home.html', username=session['username'])
    else:
        return redirect(url_for('home'))

@app.route('/manage_employees')
def manage_employees():
    if 'username' in session and session.get('access_level') == 'CEO':
        # Add logic for managing employees here
        return render_template('manage_employees.html')
    else:
        return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=5010)
