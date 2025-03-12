from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    profile_picture = db.Column(db.String(120), nullable=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    members = db.relationship('User', secondary='group_members', backref='groups')

group_members = db.Table('group_members',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('Email already exists')
        return redirect(url_for('signup'))
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    user = User(username=username, email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home.html', username=session.get('username'))

@app.route('/notes')
def notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('notes.html', username=session.get('username'))

@app.route('/community')
def community():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('community.html', username=session.get('username'))

@app.route('/games')
def games():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('games.html', username=session.get('username'))

@app.route('/game1')
def game1():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('game1.html', username=session.get('username'))

@app.route('/game2')
def game2():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('game2.html', username=session.get('username'))

@app.route('/game3')
def game3():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('game3.html', username=session.get('username'))

@app.route('/game4')
def game4():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('game4.html', username=session.get('username'))

@app.route('/game5')
def game5():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('game5.html', username=session.get('username'))

@app.route('/charts')
def charts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('charts.html', username=session.get('username'))

@app.route('/search_users', methods=['GET'])
def search_users():
    query = request.args.get('query')
    users = User.query.filter(User.username.contains(query)).all()
    return jsonify([{'id': user.id, 'username': user.username, 'profile_picture': user.profile_picture} for user in users])

@app.route('/send_message', methods=['POST'])
def send_message():
    sender_id = request.form['sender_id']
    receiver_id = request.form['receiver_id']
    content = request.form['content']
    message = Message(sender_id=sender_id, receiver_id=receiver_id, content=content)
    db.session.add(message)
    db.session.commit()
    return jsonify({'status': 'Message sent'})

@app.route('/create_group', methods=['POST'])
def create_group():
    group_name = request.form['group_name']
    member_ids = request.form.getlist('member_ids')
    group = Group(name=group_name)
    for member_id in member_ids:
        user = User.query.get(member_id)
        group.members.append(user)
    db.session.add(group)
    db.session.commit()
    return jsonify({'status': 'Group created'})

@app.route('/chat/<int:user_id>')
def chat(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if not user:
        flash('User not found')
        return redirect(url_for('dashboard'))
    messages = Message.query.filter(
        ((Message.sender_id == session['user_id']) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == session['user_id']))
    ).order_by(Message.timestamp).all()
    
    # Mark messages as read
    for message in messages:
        if message.receiver_id == session['user_id']:
            message.read = True
    db.session.commit()
    
    return render_template('chat.html', user=user, messages=messages, username=session.get('username'))

@app.route('/group_chat/<int:group_id>')
def group_chat(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found')
        return redirect(url_for('dashboard'))
    return render_template('group_chat.html', group=group, username=session.get('username'))

@app.route('/unread_messages', methods=['GET'])
def unread_messages():
    if 'user_id' not in session:
        return jsonify({'count': 0})
    user_id = session['user_id']
    count = Message.query.filter_by(receiver_id=user_id, read=False).count()
    return jsonify({'count': count})

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            # Here you would send an email with a recovery link
            flash('Password recovery instructions have been sent to your email.')
        else:
            flash('Email not found.')
    return render_template('recover.html')

@app.route('/threat_detection')
def threat_detection():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('threat_detection.html', username=session.get('username'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Ensure the 'read' column exists in the 'message' table
        try:
            db.engine.execute('ALTER TABLE message ADD COLUMN read BOOLEAN DEFAULT FALSE')
        except Exception as e:
            print(f"Column 'read' already exists or error occurred: {e}")
    app.run(debug=True)