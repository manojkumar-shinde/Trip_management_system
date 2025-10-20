from flask import Flask, request, redirect, url_for, render_template, flash, abort, jsonify
from werkzeug.utils import secure_filename
import os
import uuid
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
eventlet = None
try:
    from flask_socketio import SocketIO, join_room, leave_room, emit
    SOCKETIO_ENABLED = True
except Exception:
    SOCKETIO_ENABLED = False
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField, SelectField, SelectMultipleField, DecimalField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import date

# --- Initialize app ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret'  # change in production
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
# Upload settings
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Database config and init ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tripsync.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- Login manager ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- SocketIO (optional) ---
socketio = None
if SOCKETIO_ENABLED:
    # initialize SocketIO (don't force monkey-patching here)
    socketio = SocketIO(app, cors_allowed_origins='*', logger=True, engineio_logger=True)

# --- User model ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Trip model ---
class Trip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    title = db.Column(db.String(120), nullable=False)
    destination = db.Column(db.String(120), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    description = db.Column(db.Text, nullable=True)
    cover_image = db.Column(db.String(255), nullable=True)

    owner = db.relationship('User', backref='trips')


# --- Itinerary model ---
class ItineraryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trip_id = db.Column(db.Integer, db.ForeignKey('trip.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    datetime = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200), nullable=True)
    cost = db.Column(db.Numeric(10,2), nullable=True)
    tags = db.Column(db.String(255), nullable=True)

    trip = db.relationship('Trip', backref='itinerary_items')


# --- Phase 3: Groups & Membership ---
class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    admin = db.relationship('User', backref='owned_groups')
    members = db.relationship('GroupMember', backref='group', cascade='all, delete-orphan')


class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='member')

    user = db.relationship('User', backref='group_memberships')


# --- Chat Messages ---
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    media_filename = db.Column(db.String(255), nullable=True)
    location_lat = db.Column(db.Float, nullable=True)
    location_lng = db.Column(db.Float, nullable=True)
    location_label = db.Column(db.String(255), nullable=True)

    user = db.relationship('User')
    group = db.relationship('Group', backref='messages')


# --- Phase 5: Expenses & Budgeting ---
# association table for many-to-many participants
expense_participants = db.Table('expense_participants',
    db.Column('expense_id', db.Integer, db.ForeignKey('expense.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trip_id = db.Column(db.Integer, db.ForeignKey('trip.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Numeric(12,2), nullable=False)
    payer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    notes = db.Column(db.Text, nullable=True)

    trip = db.relationship('Trip', backref='expenses')
    payer = db.relationship('User', foreign_keys=[payer_id])
    participants = db.relationship('User', secondary=expense_participants, backref='expenses_participated')



@app.route('/groups/<int:group_id>/messages')
@login_required
def get_group_messages(group_id):
    grp = Group.query.get_or_404(group_id)
    # membership check
    if not GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first():
        return jsonify({'error': 'not a member'}), 403
    msgs = Message.query.filter_by(group_id=group_id).order_by(Message.timestamp.asc()).limit(200).all()
    result = []
    for m in msgs:
        result.append({
            'id': m.id,
            'user': m.user.name,
            'user_id': m.user_id,
            'text': m.text,
            'timestamp': m.timestamp.isoformat(),
            'media_filename': m.media_filename,
            'location_lat': m.location_lat,
            'location_lng': m.location_lng,
            'location_label': m.location_label,
        })
    return jsonify(result)


@app.route('/groups/<int:group_id>/upload', methods=['POST'])
@login_required
def upload_group_media(group_id):
    grp = Group.query.get_or_404(group_id)
    if not GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first():
        return jsonify({'error': 'not a member'}), 403
    # Quick content-length check (Flask will also enforce MAX_CONTENT_LENGTH)
    if request.content_length is not None and request.content_length > app.config.get('MAX_CONTENT_LENGTH', 0):
        return jsonify({'error': 'file too large'}), 413
    if 'file' not in request.files:
        return jsonify({'error': 'no file'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'empty filename'}), 400
    filename = secure_filename(f.filename)
    # validate extension
    if not allowed_file(filename):
        return jsonify({'error': 'file type not allowed'}), 400
    # prefix with uuid to avoid collisions
    unique_name = f"{uuid.uuid4().hex}_{filename}"
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
    try:
        f.save(save_path)
    except Exception as e:
        app.logger.exception('Failed to save uploaded file')
        return jsonify({'error': 'failed to save file'}), 500
    from datetime import datetime
    msg = Message(group_id=group_id, user_id=current_user.id, text='', timestamp=datetime.utcnow(), media_filename=unique_name)
    db.session.add(msg)
    db.session.commit()
    # emit
    room = f'group_{group_id}'
    media_url = url_for('static', filename=f'uploads/{msg.media_filename}')
    payload = {'id': msg.id, 'user': current_user.name, 'user_id': current_user.id, 'text': '', 'timestamp': msg.timestamp.isoformat(), 'media_filename': msg.media_filename, 'media_url': media_url}
    if SOCKETIO_ENABLED and socketio is not None:
        socketio.emit('message', payload, room=room)
    return jsonify({'ok': True, 'message': payload})


@app.route('/groups/<int:group_id>/share_location', methods=['POST'])
@login_required
def share_location(group_id):
    grp = Group.query.get_or_404(group_id)
    if not GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first():
        return jsonify({'error': 'not a member'}), 403
    data = request.get_json() or {}
    lat = data.get('lat')
    lng = data.get('lng')
    label = data.get('label')
    if lat is None or lng is None:
        return jsonify({'error': 'lat/lng required'}), 400
    from datetime import datetime
    msg = Message(group_id=group_id, user_id=current_user.id, text=label or '', timestamp=datetime.utcnow(), location_lat=float(lat), location_lng=float(lng), location_label=label)
    db.session.add(msg)
    db.session.commit()
    room = f'group_{group_id}'
    payload = {'id': msg.id, 'user': current_user.name, 'user_id': current_user.id, 'text': msg.text, 'timestamp': msg.timestamp.isoformat(), 'location_lat': msg.location_lat, 'location_lng': msg.location_lng, 'location_label': msg.location_label}
    if SOCKETIO_ENABLED and socketio is not None:
        socketio.emit('message', payload, room=room)
    return jsonify({'ok': True, 'message': payload})


if SOCKETIO_ENABLED:
    @socketio.on('connect')
    def handle_connect():
        sid = request.sid if hasattr(request, 'sid') else 'unknown'
        app.logger.info(f"SocketIO: connect sid={sid} user_authenticated={current_user.is_authenticated}")
        # Log handshake-related headers to help debug websocket upgrade
        try:
            hdrs = {k: v for k, v in request.headers.items() if k.lower() in ('upgrade','connection','origin','cookie') or k.lower().startswith('sec-')}
            app.logger.info(f"SocketIO: connect headers={hdrs}")
        except Exception as e:
            app.logger.info(f"SocketIO: failed to read headers: {e}")
        if not current_user.is_authenticated:
            app.logger.info('SocketIO: unauthenticated socket connection')

    @socketio.on('disconnect')
    def handle_disconnect():
        sid = request.sid if hasattr(request, 'sid') else 'unknown'
        app.logger.info(f"SocketIO: disconnect sid={sid} user={getattr(current_user,'id',None)}")

    @socketio.on('join')
    def handle_join(data):
        group_id = data.get('group')
        if not group_id:
            emit('error', {'message': 'missing group id'})
            return
        app.logger.info(f"SocketIO: join request group={group_id} user={getattr(current_user,'id',None)}")
        # verify membership
        if not current_user.is_authenticated or not GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first():
            emit('error', {'message': 'not a member or not authenticated'})
            return
        room = f'group_{group_id}'
        join_room(room)
        app.logger.info(f"SocketIO: {current_user.name} joined room {room}")
        # notify the joining client that they have joined
        emit('joined', {'group': group_id})
        # broadcast status to room
        emit('status', {'message': f'{current_user.name} has joined the chat.'}, room=room)

    @socketio.on('leave')
    def handle_leave(data):
        group_id = data.get('group')
        app.logger.info(f"SocketIO: leave request group={group_id} user={getattr(current_user,'id',None)}")
        if not group_id:
            return
        room = f'group_{group_id}'
        leave_room(room)
        app.logger.info(f"SocketIO: {getattr(current_user,'name',None)} left room {room}")
        # notify client and broadcast
        emit('left', {'group': group_id})
        emit('status', {'message': f'{getattr(current_user,"name", "A user")} has left the chat.'}, room=room)

    @socketio.on('message')
    def handle_message(data):
        group_id = data.get('group')
        text = data.get('text')
        app.logger.info(f"SocketIO: message incoming group={group_id} user={getattr(current_user,'id',None)} text_present={bool(text)}")
        if not group_id or not text:
            emit('error', {'message': 'group and text required'})
            return
        # membership check
        if not current_user.is_authenticated or not GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first():
            emit('error', {'message': 'not a member or not authenticated'})
            return
        from datetime import datetime
        msg = Message(group_id=group_id, user_id=current_user.id, text=text, timestamp=datetime.utcnow())
        db.session.add(msg)
        db.session.commit()
        app.logger.info(f"SocketIO: message saved id={msg.id} group={group_id} user={current_user.id}")
        room = f'group_{group_id}'
        emit('message', {'id': msg.id, 'user': current_user.name, 'user_id': current_user.id, 'text': text, 'timestamp': msg.timestamp.isoformat()}, room=room)


class GroupForm(FlaskForm):
    name = StringField('Group Name', validators=[InputRequired(), Length(1,120)])
    description = TextAreaField('Description')
    submit = SubmitField('Create')

# --- Forms ---
class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(1,50)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(6,128)])
    confirm = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class TripForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(1,120)])
    destination = StringField('Destination', validators=[InputRequired(), Length(1,120)])
    start_date = DateField('Start date', validators=[InputRequired()], format='%Y-%m-%d')
    end_date = DateField('End date', validators=[InputRequired()], format='%Y-%m-%d')
    description = TextAreaField('Description')
    submit = SubmitField('Save')


class ItineraryForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(1,200)])
    description = TextAreaField('Description')
    datetime = DateField('Date', validators=[InputRequired()], format='%Y-%m-%d')
    location = StringField('Location')
    cost = StringField('Cost')
    tags = StringField('Tags (comma separated)')
    submit = SubmitField('Save')


class ExpenseForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(1,200)])
    amount = StringField('Amount (USD)', validators=[InputRequired()])
    payer = SelectField('Payer', coerce=int, validators=[InputRequired()])
    participants = SelectMultipleField('Participants', coerce=int)
    notes = TextAreaField('Notes')
    submit = SubmitField('Save')

def is_trip_member(trip_id, user_id):
    # trip owner or group member? For now, allow trip owner only and later extend if group-membership linked
    t = Trip.query.get(trip_id)
    if not t:
        return False
    if t.user_id == user_id:
        return True
    # if trip is linked to a group, check group membership
    if getattr(t, 'group_id', None):
        return GroupMember.query.filter_by(group_id=t.group_id, user_id=user_id).first() is not None
    return False

def compute_balances(trip_id):
    """Return dict user_id -> balance (positive means user is owed money, negative means owes)."""
    expenses = Expense.query.filter_by(trip_id=trip_id).all()
    balances = {}
    for exp in expenses:
        total = float(exp.amount)
        parts = exp.participants or []
        if isinstance(parts, list) and len(parts) > 0:
            share = total / len(parts)
        else:
            # if no participants listed, assume payer only (no split)
            share = 0
        # payer is owed total - share (or total if no participants)
        payer_id = exp.payer_id
        balances.setdefault(payer_id, 0.0)
        if share == 0:
            balances[payer_id] += total
        else:
            balances[payer_id] += (total - share)
        # each participant owes share
        if isinstance(parts, list):
            for u in parts:
                balances.setdefault(u, 0.0)
                balances[u] -= share
    return balances


def compute_settlements(balances):
    """Given balances dict user_id->balance, return list of settlements: from, to, amount."""
    # creditors: positive balance (is owed); debtors: negative (owes)
    creditors = []
    debtors = []
    for uid, bal in balances.items():
        amt = round(bal, 2)
        if amt > 0:
            creditors.append([uid, amt])
        elif amt < 0:
            debtors.append([uid, -amt])  # store positive owed amount
    creditors.sort(key=lambda x: x[1], reverse=True)
    debtors.sort(key=lambda x: x[1], reverse=True)
    settlements = []
    i = 0
    j = 0
    while i < len(debtors) and j < len(creditors):
        debtor_id, owe_amt = debtors[i]
        creditor_id, cred_amt = creditors[j]
        take = min(owe_amt, cred_amt)
        settlements.append({'from': debtor_id, 'to': creditor_id, 'amount': round(take,2)})
        debtors[i][1] -= take
        creditors[j][1] -= take
        if debtors[i][1] == 0:
            i += 1
        if creditors[j][1] == 0:
            j += 1
    return settlements

# Expenses routes
@app.route('/trip/<int:trip_id>/expenses')
@login_required
def trip_expenses(trip_id):
    trip = Trip.query.get_or_404(trip_id)
    # allow trip owner or participants — using owner check for now
    # TODO: extend to group members if trips can be shared
    if not is_trip_member(trip_id, current_user.id):
        abort(403)
    expenses = Expense.query.filter_by(trip_id=trip_id).order_by(Expense.id.desc()).all()
    # prepare participants display
    exp_list = []
    for e in expenses:
        exp_list.append({
            'id': e.id,
            'title': e.title,
            'amount': float(e.amount),
            'payer': e.payer.name if e.payer else 'Unknown',
            'participants': [u.name for u in e.participants],
            'notes': e.notes
        })
    balances = compute_balances(trip_id)
    # translate balances to readable form
    user_balances = []
    # get all users involved: trip owner + participants + payers
    user_ids = set(balances.keys())
    for e in expenses:
        user_ids.update([u.id for u in e.participants])
        user_ids.add(e.payer_id)
    users = User.query.filter(User.id.in_(list(user_ids))).all() if user_ids else []
    user_map = {u.id: u for u in users}
    for uid in user_ids:
        u = user_map.get(uid)
        user_balances.append({'user_id': uid, 'name': u.name if u else 'Unknown', 'balance': round(balances.get(uid, 0.0),2)})
    # compute settlements
    settlements_raw = compute_settlements(balances)
    settlements = []
    for s in settlements_raw:
        settlements.append({'from': s['from'], 'to': s['to'], 'amount': s['amount'], 'from_name': user_map.get(s['from']).name if user_map.get(s['from']) else str(s['from']), 'to_name': user_map.get(s['to']).name if user_map.get(s['to']) else str(s['to'])})
    return render_template('trip_expenses.html', trip=trip, expenses=exp_list, balances=user_balances, settlements=settlements)


@app.route('/trip/<int:trip_id>/expenses/create', methods=['GET','POST'])
@login_required
def create_expense(trip_id):
    trip = Trip.query.get_or_404(trip_id)
    if not is_trip_member(trip_id, current_user.id):
        abort(403)
    form = ExpenseForm()
    # populate payer/participants choices from users involved in the trip: owner + group members
    users_q = [trip.owner]
    if getattr(trip, 'group_id', None):
        members = GroupMember.query.filter_by(group_id=trip.group_id).all()
        users_q = [trip.owner] + [m.user for m in members]
    # dedupe
    seen = set()
    choices = []
    for u in users_q:
        if u and u.id not in seen:
            seen.add(u.id)
            choices.append((u.id, f"{u.name} (id:{u.id})"))
    form.payer.choices = choices
    form.participants.choices = choices
    # populate simple payer/participants fields during GET
    if form.validate_on_submit():
        title = form.title.data
        try:
            amount = float(form.amount.data)
        except Exception:
            flash('Invalid amount', 'danger')
            return render_template('create_expense.html', trip=trip, form=form)
        payer_id = form.payer.data
        participant_ids = form.participants.data or []
        notes = form.notes.data
        exp = Expense(trip_id=trip_id, title=title, amount=amount, payer_id=payer_id, notes=notes)
        # attach participants
        if participant_ids:
            users = User.query.filter(User.id.in_(participant_ids)).all()
            exp.participants = users
        db.session.add(exp)
        db.session.commit()
        flash('Expense added', 'success')
        return redirect(url_for('trip_expenses', trip_id=trip_id))
    return render_template('create_expense.html', trip=trip, form=form)


@app.route('/expenses/<int:expense_id>/edit', methods=['GET','POST'])
@login_required
def edit_expense(expense_id):
    exp = Expense.query.get_or_404(expense_id)
    if not is_trip_member(exp.trip_id, current_user.id):
        abort(403)
    form = ExpenseForm()
    # populate payer/participants choices like in create
    trip = exp.trip
    users_q = [trip.owner]
    if getattr(trip, 'group_id', None):
        members = GroupMember.query.filter_by(group_id=trip.group_id).all()
        users_q = [trip.owner] + [m.user for m in members]
    seen = set()
    choices = []
    for u in users_q:
        if u and u.id not in seen:
            seen.add(u.id)
            choices.append((u.id, f"{u.name} (id:{u.id})"))
    form.payer.choices = choices
    form.participants.choices = choices
    if form.validate_on_submit():
        exp.title = form.title.data
        try:
            exp.amount = float(form.amount.data)
        except Exception:
            flash('Invalid amount', 'danger')
            return render_template('create_expense.html', trip=exp.trip, form=form)
        exp.payer_id = form.payer.data
        participant_ids = form.participants.data or []
        if participant_ids:
            exp.participants = User.query.filter(User.id.in_(participant_ids)).all()
        else:
            exp.participants = []
        exp.notes = form.notes.data
        db.session.commit()
        flash('Expense updated', 'success')
        return redirect(url_for('trip_expenses', trip_id=exp.trip_id))
    # populate form
    if request.method == 'GET':
        form.title.data = exp.title
        form.amount.data = str(float(exp.amount))
        form.payer.data = exp.payer_id
        form.participants.data = [u.id for u in exp.participants]
        form.notes.data = exp.notes
    return render_template('create_expense.html', trip=exp.trip, form=form)


@app.route('/expenses/<int:expense_id>/delete', methods=['POST'])
@login_required
def delete_expense(expense_id):
    exp = Expense.query.get_or_404(expense_id)
    if not is_trip_member(exp.trip_id, current_user.id):
        abort(403)
    db.session.delete(exp)
    db.session.commit()
    flash('Expense deleted', 'info')
    return redirect(url_for('trip_expenses', trip_id=exp.trip_id))

# --- Routes ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered', 'warning')
            return render_template('register.html', form=form)

        user = User(name=form.name.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("Registration successful!", "success")
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid email or password.", "danger")
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('home'))


# --- Dashboard & Trip CRUD ---
@app.route('/dashboard')
@login_required
def dashboard():
    today = date.today()
    trips = Trip.query.filter_by(user_id=current_user.id).order_by(Trip.start_date).all()
    upcoming = [t for t in trips if t.start_date > today]
    ongoing = [t for t in trips if t.start_date <= today <= t.end_date]
    completed = [t for t in trips if t.end_date < today]
    return render_template('dashboard.html', upcoming=upcoming, ongoing=ongoing, completed=completed)


@app.route('/create_trip', methods=['GET', 'POST'])
@login_required
def create_trip():
    form = TripForm()
    if form.validate_on_submit():
        trip = Trip(
            user_id=current_user.id,
            title=form.title.data,
            destination=form.destination.data,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            description=form.description.data,
        )
        db.session.add(trip)
        db.session.commit()
        flash('Trip created', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_trip.html', form=form)


@app.route('/view_trip/<int:trip_id>')
@login_required
def view_trip(trip_id):
    trip = Trip.query.get_or_404(trip_id)
    if trip.user_id != current_user.id:
        abort(403)
    # show itinerary items grouped by date for the trip
    items = ItineraryItem.query.filter_by(trip_id=trip.id).order_by(ItineraryItem.datetime).all()
    # build a list of dates present
    from collections import defaultdict
    grouped = defaultdict(list)
    for it in items:
        grouped[it.datetime.date()].append(it)

    sorted_dates = sorted(grouped.keys())
    return render_template('view_trip.html', trip=trip, itinerary_items=items, grouped_itinerary=grouped, itinerary_dates=sorted_dates)


@app.route('/trip/<int:trip_id>/itinerary/create', methods=['GET', 'POST'])
@login_required
def create_itinerary(trip_id):
    trip = Trip.query.get_or_404(trip_id)
    if trip.user_id != current_user.id:
        abort(403)
    form = ItineraryForm()
    if form.validate_on_submit():
        from datetime import datetime
        dt = datetime.combine(form.datetime.data, datetime.min.time())
        item = ItineraryItem(
            trip_id=trip.id,
            title=form.title.data,
            description=form.description.data,
            datetime=dt,
            location=form.location.data,
            cost=(float(form.cost.data) if form.cost.data else None),
            tags=form.tags.data,
        )
        db.session.add(item)
        db.session.commit()
        flash('Itinerary item added', 'success')
        return redirect(url_for('view_trip', trip_id=trip.id))
    return render_template('create_itinerary.html', form=form, trip=trip)


@app.route('/itinerary/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_itinerary(item_id):
    item = ItineraryItem.query.get_or_404(item_id)
    trip = item.trip
    if trip.user_id != current_user.id:
        abort(403)
    form = ItineraryForm(obj=item)
    if form.validate_on_submit():
        from datetime import datetime
        item.title = form.title.data
        item.description = form.description.data
        item.datetime = datetime.combine(form.datetime.data, datetime.min.time())
        item.location = form.location.data
        item.cost = (float(form.cost.data) if form.cost.data else None)
        item.tags = form.tags.data
        db.session.commit()
        flash('Itinerary updated', 'success')
        return redirect(url_for('view_trip', trip_id=trip.id))
    return render_template('edit_itinerary.html', form=form, trip=trip, item=item)


@app.route('/itinerary/<int:item_id>/delete', methods=['POST'])
@login_required
def delete_itinerary(item_id):
    item = ItineraryItem.query.get_or_404(item_id)
    trip = item.trip
    if trip.user_id != current_user.id:
        abort(403)
    db.session.delete(item)
    db.session.commit()
    flash('Itinerary item deleted', 'info')
    return redirect(url_for('view_trip', trip_id=trip.id))


@app.route('/edit_trip/<int:trip_id>', methods=['GET', 'POST'])
@login_required
def edit_trip(trip_id):
    trip = Trip.query.get_or_404(trip_id)
    if trip.user_id != current_user.id:
        abort(403)
    form = TripForm(obj=trip)
    if form.validate_on_submit():
        trip.title = form.title.data
        trip.destination = form.destination.data
        trip.start_date = form.start_date.data
        trip.end_date = form.end_date.data
        trip.description = form.description.data
        db.session.commit()
        flash('Trip updated', 'success')
        return redirect(url_for('view_trip', trip_id=trip.id))
    return render_template('edit_trip.html', form=form, trip=trip)


@app.route('/delete_trip/<int:trip_id>', methods=['POST'])
@login_required
def delete_trip(trip_id):
    trip = Trip.query.get_or_404(trip_id)
    if trip.user_id != current_user.id:
        abort(403)
    db.session.delete(trip)
    db.session.commit()
    flash('Trip deleted', 'info')
    return redirect(url_for('dashboard'))


@app.route('/groups')
@login_required
def groups():
    # Show groups the current user belongs to and all groups
    all_groups = Group.query.order_by(Group.name).all()
    # Use an explicit join to ensure members are returned even if backrefs are stale
    my_groups = Group.query.join(GroupMember).filter(GroupMember.user_id == current_user.id).order_by(Group.name).all()
    return render_template('groups.html', all_groups=all_groups, my_groups=my_groups)


@app.route('/groups/create', methods=['GET', 'POST'])
@login_required
def create_group():
    form = GroupForm()
    if form.validate_on_submit():
        grp = Group(name=form.name.data, description=form.description.data, admin_id=current_user.id)
        db.session.add(grp)
        db.session.commit()
        # add creator as admin member
        gm = GroupMember(group_id=grp.id, user_id=current_user.id, role='admin')
        db.session.add(gm)
        db.session.commit()
        flash('Group created', 'success')
        return redirect(url_for('group_detail', group_id=grp.id))
    return render_template('create_group.html', form=form)


@app.route('/groups/<int:group_id>')
@login_required
def group_detail(group_id):
    grp = Group.query.get_or_404(group_id)
    members = [gm.user for gm in grp.members]
    is_member = any(gm.user_id == current_user.id for gm in grp.members)
    return render_template('group_detail.html', group=grp, members=members, is_member=is_member, current_user_id=current_user.id)


@app.route('/socket_diag')
def socket_diag():
    # diagnostic endpoint to check whether cookies/session are sent from the browser
    info = {
        'cookies': dict(request.cookies),
        'headers': {k: v for k, v in request.headers.items()},
        'is_authenticated': bool(current_user.is_authenticated) if 'current_user' in globals() else False,
    }
    return jsonify(info)


@app.route('/groups/<int:group_id>/join', methods=['POST'])
@login_required
def join_group(group_id):
    grp = Group.query.get_or_404(group_id)
    if any(gm.user_id == current_user.id for gm in grp.members):
        flash('Already a member', 'info')
        return redirect(url_for('group_detail', group_id=group_id))
    gm = GroupMember(group_id=group_id, user_id=current_user.id, role='member')
    db.session.add(gm)
    db.session.commit()
    flash('Joined group', 'success')
    return redirect(url_for('group_detail', group_id=group_id))


@app.route('/groups/<int:group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    grp = Group.query.get_or_404(group_id)
    gm = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not gm:
        flash('Not a member', 'warning')
        return redirect(url_for('group_detail', group_id=group_id))
    # prevent admin from leaving if they're the only admin
    if gm.role == 'admin':
        other_admin = GroupMember.query.filter(GroupMember.group_id==group_id, GroupMember.user_id!=current_user.id, GroupMember.role=='admin').first()
        if not other_admin:
            flash('Transfer admin role before leaving', 'warning')
            return redirect(url_for('group_detail', group_id=group_id))
    db.session.delete(gm)
    db.session.commit()
    flash('Left group', 'info')
    return redirect(url_for('groups'))

# --- Run server ---
if __name__ == '__main__':
    if SOCKETIO_ENABLED and socketio is not None:
        # when SocketIO is available use its runner
        socketio.run(app, debug=True)
    else:
        app.run(debug=True)
