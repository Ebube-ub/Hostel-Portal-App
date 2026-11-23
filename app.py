import os

from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_bcrypt import Bcrypt
from functools import wraps


app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hostel.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'thisisasecretkey')

# The preview panel embeds this app in a cross-site iframe. Browsers refuse to
# send a SameSite=Lax cookie in that context, which makes login look successful
# and then bounce straight back to /login. SameSite=None + Secure fixes it, but
# Secure cookies need https, so it is opt-in rather than the default for local
# http development.
if os.environ.get('SESSION_COOKIE_SECURE') == '1':
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'None'
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Room types and the layout used to seed an empty database.
# Private rooms take one student, shared rooms take two.
ROOM_CAPACITY = {'private': 1, 'shared': 2}
ROOM_LAYOUT = [
    ('Room101', 'private'),
    ('Room102', 'private'),
    ('Room103', 'private'),
    ('Room104', 'private'),
    ('Room105', 'shared'),
    ('Room106', 'shared'),
    ('Room107', 'private'),
    ('Room108', 'shared'),
    ('Room109', 'private'),
]


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    selected_room = db.Column(db.String(10))  # e.g., Room101
    complaint = db.Column(db.String(200), unique=True, nullable=True)

    @property
    def is_admin(self):
        """True when this account holds the admin role."""
        return UserRole.query.filter_by(user_id=self.id, role='admin').first() is not None


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    room_name = db.Column(db.String(50), nullable=False)
    check_in = db.Column(db.DateTime, default=db.func.now())
    status = db.Column(db.String(20), default='active')  # pending, awaiting_student, active, cancelled, completed
    student_name = db.Column(db.String(120))  # filled by a warden making a reservation
    student_id = db.Column(db.String(40))
    previous_room = db.Column(db.String(50))  # room given up by a rebooking request
    reason = db.Column(db.String(300))        # why the student wants to move

    user = db.relationship('User', backref=db.backref('bookings', lazy=True))


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    room_type = db.Column(db.String(20), nullable=False, default='private')  # private, shared
    capacity = db.Column(db.Integer, nullable=False, default=1)
    status = db.Column(db.String(20), default='available')  # available, occupied, maintenance, reserved

    @property
    def display_name(self):
        """'Room101' reads better as 'Room 101'."""
        if self.name.startswith('Room') and self.name[4:].isdigit():
            return f'Room {self.name[4:]}'
        return self.name

    @property
    def active_bookings(self):
        return Booking.query.filter_by(room_name=self.name, status='active').all()

    @property
    def occupied_beds(self):
        return Booking.query.filter_by(room_name=self.name, status='active').count()

    @property
    def pending_bookings(self):
        return Booking.query.filter(Booking.room_name == self.name,
                                    Booking.status.in_(('pending', 'awaiting_student'))).all()

    @property
    def pending_beds(self):
        return len(self.pending_bookings)

    @property
    def free_beds(self):
        # a pending request holds its bed until the warden answers it
        return max(self.capacity - self.occupied_beds - self.pending_beds, 0)

    @property
    def is_available(self):
        return self.status not in ('maintenance', 'reserved') and self.free_beds > 0

    @property
    def occupants(self):
        return [booking.user for booking in self.active_bookings if booking.user is not None]


class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)


class Notification(db.Model):
    """In-app message shown in the navbar bell."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(240), nullable=False)
    link = db.Column(db.String(200))
    kind = db.Column(db.String(20), default='info')
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    user = db.relationship('User', backref=db.backref('notifications', lazy=True))

class ComplaintForm(FlaskForm):
    complaint = StringField(validators=[Length(min=4, max=220)], render_kw={"placeholder": "Any Complaint?"})
    submit = SubmitField('Submit Complaint')

class RoomIssue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    room_name = db.Column(db.String(50))
    description = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, in_progress, resolved
    priority = db.Column(db.String(20), default='medium')  # low, medium, high
    created_at = db.Column(db.DateTime, default=db.func.now())
    resolved_at = db.Column(db.DateTime)


class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message='Invalid email'), Length(max=150)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=150)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()


        if existing_user_email:
            raise ValidationError('That user already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message='Invalid email'), Length(max=150)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=150)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            flash('That user already exists. Please choose a different one.')
            raise ValidationError('That user already exists. Please choose a different one.')


def create_default_rooms():
    """Seed the nine rooms from ROOM_LAYOUT, but only into an empty table."""
    if Room.query.count() > 0:
        return 0
    for name, room_type in ROOM_LAYOUT:
        db.session.add(Room(name=name, room_type=room_type, capacity=ROOM_CAPACITY[room_type]))
    db.session.commit()
    return len(ROOM_LAYOUT)


def refresh_room_status(room):
    """Keep Room.status in step with the active bookings.

    A room becomes 'occupied' once every bed is taken. An admin-set
    'maintenance' or 'reserved' flag is never overwritten here.
    """
    if room.status in ('maintenance', 'reserved'):
        return
    room.status = 'occupied' if room.free_beds <= 0 else 'available'


def notify(user_id, message, link=None, kind='info'):
    """Queue an in-app notification for one account."""
    if user_id is None:
        return
    db.session.add(Notification(user_id=user_id, message=message, link=link, kind=kind))


def notify_admins(message, link=None, kind='info'):
    """Every account holding the admin role hears about it."""
    for role in UserRole.query.filter_by(role='admin').all():
        notify(role.user_id, message, link, kind)


def room_label(name):
    """'Room101' reads better as 'Room 101'; fall back to whatever we were given."""
    room = Room.query.filter_by(name=name).first() if name else None
    return room.display_name if room else (name or 'that room')


def active_booking_for(user_id):
    """The student's one approved bed, if they have one."""
    return (Booking.query.filter_by(user_id=user_id, status='active')
            .order_by(Booking.id.desc()).first())


def open_booking_request(user_id):
    """A first booking still waiting on the warden, or on the student."""
    return (Booking.query.filter(Booking.user_id == user_id,
                                 Booking.status.in_(('pending', 'awaiting_student')))
            .order_by(Booking.id.desc()).first())


def rebooking_request_for(user_id):
    """A room-change request still waiting on the warden."""
    return (Booking.query.filter_by(user_id=user_id, status='rebooking_pending')
            .order_by(Booking.id.desc()).first())


def booking_conflict(user_id, who=None):
    """Why this student cannot be given another room, or None when they can.

    Reads the live booking rows themselves, so a warden who posts the
    reservation form directly (or refreshes it) is stopped by the same rule the
    page shows. One student gets one live record at a time: an approved room, a
    pending request, a warden reservation, or a rebooking request.
    """
    who = who or 'This student'

    # A rebooking request outranks the room it would replace: the move waiting
    # on the warden is the thing that has to be answered, not a new reservation.
    rebooking = rebooking_request_for(user_id)
    if rebooking is not None:
        return (f'{who} already has a pending rebooking request '
                f'({room_label(rebooking.previous_room)} to '
                f'{room_label(rebooking.room_name)}). Approve or reject it in '
                'the Bookings tab instead of creating another reservation.')

    request_row = open_booking_request(user_id)
    if request_row is not None:
        if request_row.status == 'awaiting_student':
            return (f'{who} already has {room_label(request_row.room_name)} '
                    'reserved and waiting for them to confirm it. Cancel that '
                    'reservation first if it needs to change.')
        return (f'{who} already has a pending booking request for '
                f'{room_label(request_row.room_name)}. Approve or decline that '
                'request in the Bookings tab instead of reserving another room.')

    active = active_booking_for(user_id)
    if active is not None:
        return (f'{who} already has an approved room '
                f'({room_label(active.room_name)}). Use a rebooking request to '
                'move them instead of reserving another room.')

    return None


def holds_a_booking(user_id):
    """True once this student has a bed or a request in flight."""
    return booking_conflict(user_id) is not None


def assigned_room_for(user_id):
    """The room this student actually lives in, or None when they have none.

    Only an approved (active) booking counts. A pending request, a warden
    reservation still waiting on the student, a rebooking request or a declined
    request never gives access to issue reporting, so the same check covers
    direct URL access and hand-posted forms.
    """
    booking = active_booking_for(user_id)
    if booking is None:
        return None
    return Room.query.filter_by(name=booking.room_name).first()


def issue_blocked_message(user_id):
    """Why this account cannot report an issue yet."""
    request_row = open_booking_request(user_id)
    if request_row is not None:
        if request_row.status == 'awaiting_student':
            return (f'Confirm the reservation for '
                    f'{room_label(request_row.room_name)} on this page before '
                    'reporting an issue. You need an approved room assignment '
                    'first.')
        return (f'Your booking request for {room_label(request_row.room_name)} '
                'is still waiting for the warden. You can report an issue once '
                'it is approved and the room is yours.')
    return ('You need an approved room assignment before you can report an '
            'issue. A room can only be reported on once the warden has '
            'approved your booking.')


def blocked_student_index():
    """Email -> warning for every student who already holds a booking.

    Handed to the reservation page so the form can warn (and disable itself)
    before the post, without the page guessing from rendered rows.
    """
    blocked = {}
    for user in User.query.order_by(User.email).all():
        if user.is_admin:
            continue
        reason = booking_conflict(user.id, user.email)
        if reason is not None:
            blocked[user.email.lower()] = reason
    return blocked


def room_has_free_bed(room, held=None):
    """Can `room` take one more resident?

    Approvals are checked against the beds that are actually assigned, not
    against requests, because the request being approved is about to become
    one of them. `held` lets an already-approved booking (a re-check, not a
    normal path) ignore itself.
    """
    if room is None or room.status in ('maintenance', 'reserved'):
        return False
    taken = room.occupied_beds
    if (held is not None and held.room_name == room.name
            and held.status == 'active'):
        taken = max(taken - 1, 0)
    return taken < room.capacity


def release_room(user):
    """Cancel everything this user holds and free up their bed."""
    room = Room.query.filter_by(name=user.selected_room).first()
    for booking in Booking.query.filter(
            Booking.user_id == user.id,
            Booking.status.in_(('active', 'pending', 'awaiting_student',
                                'rebooking_pending'))).all():
        booking.status = 'cancelled'
    user.selected_room = None
    db.session.flush()
    if room is not None:
        refresh_room_status(room)


def request_room(user, room):
    """Open a pending request for `room`; the warden still has to approve it."""
    db.session.add(Booking(user_id=user.id, room_name=room.name, status='pending'))
    user.selected_room = room.name
    db.session.flush()
    refresh_room_status(room)


@app.route('/')
def index():
    rooms = Room.query.order_by(Room.name).all()
    stats = {
        'total': len(rooms),
        'free': sum(1 for room in rooms if room.is_available),
        'private_free': sum(1 for room in rooms if room.room_type == 'private' and room.is_available),
        'shared_free': sum(1 for room in rooms if room.room_type == 'shared' and room.is_available),
    }
    # The homepage mirrors the booking rules the routes already enforce, so a
    # student never sees a call to action the backend would refuse.
    active_booking = None
    pending_request = None
    pending_rebooking = None
    if current_user.is_authenticated and not current_user.is_admin:
        active_booking = active_booking_for(current_user.id)
        pending_request = None if active_booking else open_booking_request(current_user.id)
        pending_rebooking = rebooking_request_for(current_user.id)

    return render_template('index.html', stats=stats, rooms=rooms,
                           active_booking=active_booking,
                           pending_request=pending_request,
                           pending_rebooking=pending_rebooking)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None

    if request.method == 'POST':
        # Match the email case-insensitively and without stray whitespace, so
        # "Warden@School.edu " still finds the account.
        email = (form.email.data or '').strip()
        password = form.password.data or ''

        user = User.query.filter(User.email.ilike(email)).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('You were successfully logged in')

            # Send wardens straight to the admin dashboard. An internal ?next=
            # wins, so a bounced request returns to the page that asked for it.
            target = request.args.get('next') or ''
            if not target.startswith('/') or target.startswith('//'):
                target = url_for('admin') if user.is_admin else url_for('dashboard')
            return redirect(target)

        # A failed attempt has to say so - a silent reload reads as a broken form.
        error = 'Invalid email or password'
        flash(error)

    return render_template('login.html', form=form, error=error, from_signup=True)


@app.route('/dashboard', methods=['GET', 'POST'])  
@login_required  
def dashboard():
    error = None

    if request.method == 'POST':
        if current_user.is_admin:
            flash('Wardens reserve rooms for students from the Bookings tab.')
            return redirect(url_for('admin_bookings'))

        selected_room = request.form.get('room_name')
        room = Room.query.filter_by(name=selected_room).first()
        active = active_booking_for(current_user.id)
        open_request = open_booking_request(current_user.id)
        pending_move = rebooking_request_for(current_user.id)

        if room is None:
            error = "That room does not exist."
        elif active is not None:
            # An approved resident moves rooms through a rebooking request.
            flash(f'You already have {room_label(active.room_name)}. '
                  'Request a rebooking to move to another room.')
            if room.name == active.room_name:
                return redirect(url_for('bookings'))
            return redirect(url_for('request_rebooking', room=room.name))
        elif pending_move is not None:
            flash('Your rebooking request is still waiting for the warden.')
            return redirect(url_for('bookings'))
        elif open_request is not None:
            flash('You already have a booking request waiting for the warden.')
            return redirect(url_for('bookings'))
        elif not room.is_available:
            error = f"Sorry, {room.display_name} is already full."
        else:
            request_room(current_user, room)
            notify_admins(f'{current_user.email} requested {room.display_name}',
                          link=url_for('admin_bookings'), kind='booking')
            db.session.commit()
            flash(f'Request sent for {room.display_name} - the warden will confirm it')
            return redirect(url_for('dashboard'))

    rooms = Room.query.order_by(Room.name).all()
    summary = {
        'total_rooms': len(rooms),
        'free_rooms': sum(1 for room in rooms if room.is_available),
        'total_beds': sum(room.capacity for room in rooms),
        'free_beds': sum(room.free_beds for room in rooms),
    }
    active_booking = active_booking_for(current_user.id)
    pending_request = None if active_booking else open_booking_request(current_user.id)
    pending_rebooking = rebooking_request_for(current_user.id)
    current_booking = active_booking or pending_request

    # Only a student with nothing in flight can book, so only they are shown
    # the room list. Their last cancelled/declined record lets the page say why
    # they are free to try again instead of looking like a first visit.
    previous_request = None
    if active_booking is None and pending_request is None:
        previous_request = (Booking.query
                            .filter_by(user_id=current_user.id, status='cancelled')
                            .order_by(Booking.id.desc()).first())

    return render_template('dashboard.html', user=current_user, rooms=rooms, error=error,
                           summary=summary, current_booking=current_booking,
                           active_booking=active_booking,
                           pending_request=pending_request,
                           pending_rebooking=pending_rebooking,
                           previous_request=previous_request)




@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(email=form.email.data, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        flash('Signed Up Successfuly')
        return redirect(url_for('signup'))
       
    return render_template('signup.html', form=form)


@app.route('/cancel_selection', methods=['POST'])
@login_required
def cancel_selection():
    if not current_user.selected_room:
        flash('You do not have an active booking.')
        return redirect(url_for('dashboard'))

    release_room(current_user)
    db.session.commit()
    flash('Booking canceled')
    return redirect(url_for('dashboard'))


@app.route('/rebooking', methods=['GET', 'POST'])
@login_required
def request_rebooking():
    """Ask to swap an approved room for another one, keeping the old room
    until the warden approves the move."""
    if current_user.is_admin:
        flash('Wardens answer rebooking requests from the Bookings tab.')
        return redirect(url_for('admin_bookings'))

    active = active_booking_for(current_user.id)
    if active is None:
        flash('You need an approved room before you can request a rebooking.')
        return redirect(url_for('dashboard'))
    if rebooking_request_for(current_user.id) is not None:
        flash('You already have a rebooking request waiting for the warden.')
        return redirect(url_for('bookings'))

    rooms = [room for room in Room.query.order_by(Room.name).all()
             if room.name != active.room_name]
    form = {'room_name': request.args.get('room', ''), 'reason': ''}
    error = None

    if request.method == 'POST':
        form['room_name'] = request.form.get('room_name') or ''
        form['reason'] = (request.form.get('reason') or '').strip()
        room = Room.query.filter_by(name=form['room_name']).first()

        if room is None:
            error = 'Choose the room you would like to move to.'
        elif room.name == active.room_name:
            error = f'You already live in {room_label(active.room_name)} - pick another room.'
        elif len(form['reason']) < 4:
            error = 'Tell the warden why you want to move.'
        elif not room.is_available:
            error = f'{room.display_name} has no free bed right now.'
        else:
            db.session.add(Booking(user_id=current_user.id, room_name=room.name,
                                   status='rebooking_pending',
                                   previous_room=active.room_name,
                                   reason=form['reason']))
            notify_admins(f'{current_user.email} requested a move from '
                          f'{room_label(active.room_name)} to {room.display_name}',
                          link=url_for('admin_bookings'), kind='booking')
            db.session.commit()
            flash('Rebooking request sent - the warden will answer it soon')
            return redirect(url_for('bookings'))

    active_room = Room.query.filter_by(name=active.room_name).first()
    return render_template('rebooking.html', active_booking=active,
                           active_room=active_room, rooms=rooms,
                           form=form, error=error)


@app.route('/rebooking/withdraw', methods=['POST'])
@login_required
def withdraw_rebooking():
    """Drop a move request without touching the room the student already has."""
    pending = rebooking_request_for(current_user.id)
    if pending is None:
        flash('You have no rebooking request to withdraw.')
        return redirect(url_for('bookings'))

    pending.status = 'cancelled'
    db.session.commit()
    flash('Rebooking request withdrawn')
    return redirect(url_for('bookings'))


@app.route('/bookings', methods=['GET', 'POST'])
@login_required
def bookings():
    form = ComplaintForm()

    # Reporting is tied to the room a student was actually assigned, not to a
    # room they merely asked for. Checked on every request so a pending or
    # declined student cannot post the form by hand either.
    assigned_room = assigned_room_for(current_user.id)
    can_report_issue = assigned_room is not None

    issue_message = None if can_report_issue else issue_blocked_message(current_user.id)

    if request.method == 'POST':
        if not can_report_issue:
            flash(issue_message)
            return redirect(url_for('bookings'))
        if form.validate_on_submit():
            # Create new issue instead of storing on user
            new_issue = RoomIssue(
                email=current_user.email,
                room_name=assigned_room.name,
                description=form.complaint.data,
                status='pending',
                priority='medium')
            db.session.add(new_issue)
            notify_admins(f'{current_user.email} reported an issue in '
                          f'{assigned_room.display_name}',
                          link=url_for('admin_issues'), kind='issue')
            db.session.commit()
            flash('Complaint Submitted Successfully')
            return redirect(url_for('bookings'))

    current_room = None
    if current_user.selected_room:
        current_room = Room.query.filter_by(name=current_user.selected_room).first()

    user_bookings = Booking.query.filter_by(user_id=current_user.id)\
                                .order_by(Booking.check_in.desc())\
                                .all()
    user_issues = RoomIssue.query.filter_by(email=current_user.email)\
                             .order_by(RoomIssue.created_at.desc())\
                             .all()

    active_booking = active_booking_for(current_user.id)
    pending_request = None if active_booking else open_booking_request(current_user.id)
    current_booking = active_booking or pending_request
    pending_rebooking = rebooking_request_for(current_user.id)

    reserved = (Booking.query
                .filter_by(user_id=current_user.id, status='awaiting_student')
                .order_by(Booking.id.desc()).first())

    active_room = None
    if active_booking is not None:
        active_room = Room.query.filter_by(name=active_booking.room_name).first()

    return render_template('bookings.html',
                           form=form,
                           current_booking=current_booking,
                           active_booking=active_booking,
                           pending_request=pending_request,
                           pending_rebooking=pending_rebooking,
                           active_room=active_room,
                           reserved=reserved,
                           issues=user_issues,
                           bookings=user_bookings,
                           current_room=current_room,
                           assigned_room=assigned_room,
                           can_report_issue=can_report_issue,
                           issue_message=issue_message)


@app.route('/admin/users')
def admin_manage_users():
    if request.method == 'POST':
       current_user = request.form['content']
       new_user = User(content=current_user)
       try:
              db.session.add(new_user)
              db.session.commit()
              return redirect('/')
       except Exception as e:
              print(f"Error adding user: {e}")
              return f'ERROR: {e}'
    else:
        user = User.query.order_by(User.id).all()
    return render_template('admin.html', user=user)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        # Check if user has admin role
        admin_role = UserRole.query.filter_by(
            user_id=current_user.id, 
            role='admin'
        ).first()
        
        if not admin_role:
            flash('Access denied. Admin privileges required.')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

def get_dashboard_stats():
    """Calculate statistics for admin dashboard, counting beds rather than rooms."""
    rooms = Room.query.all()

    total_rooms = len(rooms)
    total_beds = sum(room.capacity for room in rooms)
    occupied_beds = sum(room.occupied_beds for room in rooms)

    # Occupancy rate across every bed, which is what "how full are we" means
    # once shared rooms hold two students.
    occupancy_rate = (occupied_beds / total_beds * 100) if total_beds > 0 else 0

    return {
        'total_rooms': total_rooms,
        'total_beds': total_beds,
        'occupied_beds': occupied_beds,
        'free_beds': max(total_beds - occupied_beds, 0),
        'available_rooms': sum(1 for room in rooms if room.is_available),
        'occupied_rooms': sum(1 for room in rooms if room.free_beds <= 0),
        'maintenance_rooms': sum(1 for room in rooms if room.status == 'maintenance'),
        'reserved_rooms': sum(1 for room in rooms if room.status == 'reserved'),
        'occupancy_rate': round(occupancy_rate, 1),
        'active_bookings': Booking.query.filter_by(status='active').count(),
        'pending_issues': RoomIssue.query.filter_by(status='pending').count()
    }


@app.route('/admin')
@login_required
@admin_required
def admin():
    stats = get_dashboard_stats()
    return render_template('admin.html', stats=stats)

@app.route('/admin/rooms')
@login_required
@admin_required
def admin_rooms():
    rooms = Room.query.order_by(Room.name).all()
    return render_template('admin.html', 
                         active_tab='rooms', 
                         rooms=rooms,
                         stats=get_dashboard_stats())

@app.route('/admin/room/update/<int:room_id>', methods=['POST'])
@login_required
@admin_required
def update_room_status(room_id):
    room = Room.query.get_or_404(room_id)
    new_status = request.form.get('status')
    
    if new_status in ['available', 'occupied', 'maintenance', 'reserved']:
        room.status = new_status

        # Taking a room out of service cancels the bookings in it, otherwise the
        # beds would stay occupied by students who can no longer use the room.
        if new_status == 'maintenance':
            for booking in room.active_bookings:
                booking.status = 'cancelled'
                occupant = User.query.get(booking.user_id)
                if occupant and occupant.selected_room == room.name:
                    occupant.selected_room = None

        db.session.flush()
        refresh_room_status(room)
        db.session.commit()
        flash(f'Room {room.name} status updated to {room.status}')
    
    return redirect(url_for('admin_rooms'))



@app.route('/admin/bookings')
@login_required
@admin_required
def admin_bookings():
    bookings = Booking.query.order_by(Booking.check_in.desc()).all()
    return render_template('admin.html', 
                         active_tab='bookings', 
                         bookings=bookings,
                         stats=get_dashboard_stats())

@app.route('/admin/booking/cancel/<int:booking_id>', methods=['POST'])
@login_required
@admin_required
def cancel_booking_admin(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    booking.status = 'cancelled'
    
    # Update room status
    room = Room.query.filter_by(name=booking.room_name).first()
    
    # Clear user's selection
    user = User.query.get(booking.user_id)
    if user and user.selected_room == booking.room_name:
        user.selected_room = None

    db.session.flush()
    if room:
        refresh_room_status(room)
    if user:
        label = room.display_name if room else booking.room_name
        notify(user.id, f'Your booking for {label} was cancelled by the warden',
               link=url_for('bookings'), kind='booking')
    db.session.commit()
    flash(f'Booking cancelled for {booking.room_name}')
    return redirect(url_for('admin_bookings'))


@app.route('/admin/issues')
@login_required
@admin_required
def admin_issues():
    issues = RoomIssue.query.order_by(RoomIssue.created_at.desc()).all()
    return render_template('admin.html', 
                         active_tab='issues', 
                         issues=issues,
                         stats=get_dashboard_stats())

@app.route('/admin/issue/update/<int:issue_id>', methods=['POST'])
@login_required
@admin_required
def update_issue_status(issue_id):
    issue = RoomIssue.query.get_or_404(issue_id)
    new_status = request.form.get('status')
    new_priority = request.form.get('priority')
    
    was_resolved = issue.status == 'resolved'
    if new_status:
        issue.status = new_status
        if new_status == 'resolved' and not was_resolved:
            issue.resolved_at = db.func.now()
            owner = User.query.filter(User.email.ilike(issue.email)).first()
            if owner:
                room_label = f' in {issue.room_name}' if issue.room_name else ''
                notify(owner.id, f'Your issue{room_label} was marked resolved',
                       link=url_for('bookings'), kind='issue')
    
    if new_priority:
        issue.priority = new_priority
    
    db.session.commit()
    flash('Issue updated successfully')
    return redirect(url_for('admin_issues'))

@app.route('/notifications/read/<int:notification_id>', methods=['POST'])
@login_required
def read_notification(notification_id):
    note = Notification.query.get_or_404(notification_id)
    if note.user_id != current_user.id:
        flash('That notification is not yours.')
        return redirect(request.referrer or url_for('dashboard'))
    note.is_read = True
    db.session.commit()
    return redirect(note.link or request.referrer or url_for('dashboard'))


@app.route('/notifications/read-all', methods=['POST'])
@login_required
def mark_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/admin/booking/confirm/<int:booking_id>', methods=['POST'])
@login_required
@admin_required
def confirm_booking_admin(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    room = Room.query.filter_by(name=booking.room_name).first()
    label = room.display_name if room else booking.room_name
    if booking.status != 'pending':
        flash('That booking is not waiting for confirmation.')
        return redirect(url_for('admin_bookings'))

    # One student holds one bed: a resident's older request is a room change,
    # not a second assignment.
    resident = active_booking_for(booking.user_id)
    if resident is not None:
        flash(f'That student already has {room_label(resident.room_name)} approved - '
              'process their rebooking request instead.')
        return redirect(url_for('admin_bookings'))

    # Beds can change hands between the request and this click, so check again.
    if not room_has_free_bed(room, booking):
        flash(f'{label} no longer has a free bed - the request stays pending.')
        return redirect(url_for('admin_bookings'))

    booking.status = 'active'
    db.session.flush()
    if room:
        refresh_room_status(room)
    notify(booking.user_id, f'Your booking for {label} is confirmed',
           link=url_for('bookings'), kind='booking')
    db.session.commit()
    flash(f'Booking confirmed for {booking.room_name}')
    return redirect(url_for('admin_bookings'))


@app.route('/admin/booking/decline/<int:booking_id>', methods=['POST'])
@login_required
@admin_required
def decline_booking_admin(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    room = Room.query.filter_by(name=booking.room_name).first()
    if booking.status != 'pending':
        flash('That booking is not waiting for confirmation.')
        return redirect(url_for('admin_bookings'))

    booking.status = 'cancelled'
    user = User.query.get(booking.user_id)
    if user and user.selected_room == booking.room_name:
        user.selected_room = None
    db.session.flush()
    if room:
        refresh_room_status(room)
    label = room.display_name if room else booking.room_name
    notify(booking.user_id, f'Your booking request for {label} was declined',
           link=url_for('bookings'), kind='booking')
    db.session.commit()
    flash(f'Booking declined for {booking.room_name}')
    return redirect(url_for('admin_bookings'))


@app.route('/admin/rebooking/approve/<int:booking_id>', methods=['POST'])
@login_required
@admin_required
def approve_rebooking_admin(booking_id):
    """Swap the student's room: release the old bed, hand over the new one."""
    req = Booking.query.get_or_404(booking_id)
    if req.status != 'rebooking_pending':
        flash('That request is not waiting for approval.')
        return redirect(url_for('admin_bookings'))

    room = Room.query.filter_by(name=req.room_name).first()
    if not room_has_free_bed(room):
        label = room.display_name if room else req.room_name
        flash(f'{label} has no free bed now - the request stays pending.')
        return redirect(url_for('admin_bookings'))

    student = User.query.get(req.user_id)
    previous = req.previous_room or (student.selected_room if student else None)

    # The old booking ends here; its room drops back to available.
    for booking in Booking.query.filter_by(user_id=req.user_id, status='active').all():
        if previous is None:
            previous = booking.room_name
        booking.status = 'completed'
    previous_room = Room.query.filter_by(name=previous).first()

    req.status = 'active'
    if student is not None:
        student.selected_room = room.name
    db.session.flush()
    for affected in (previous_room, room):
        if affected is not None:
            refresh_room_status(affected)

    notify(req.user_id,
           f'Your rebooking was approved - {room.display_name} is now your room',
           link=url_for('bookings'), kind='booking')
    db.session.commit()
    flash(f'{room.display_name} assigned - {room_label(previous)} is free again')
    return redirect(url_for('admin_bookings'))


@app.route('/admin/rebooking/reject/<int:booking_id>', methods=['POST'])
@login_required
@admin_required
def reject_rebooking_admin(booking_id):
    req = Booking.query.get_or_404(booking_id)
    if req.status != 'rebooking_pending':
        flash('That request is not waiting for approval.')
        return redirect(url_for('admin_bookings'))

    req.status = 'cancelled'
    student = User.query.get(req.user_id)
    kept = room_label(student.selected_room if student else None)
    notify(req.user_id, f'Your rebooking request was rejected - you keep {kept}',
           link=url_for('bookings'), kind='booking')
    db.session.commit()
    flash(f'Rebooking request rejected - the student keeps {kept}')
    return redirect(url_for('admin_bookings'))


@app.context_processor
def inject_notifications():
    """The navbar bell appears on every page, so it is filled from here."""
    if not current_user.is_authenticated:
        return {'nav_notifications': [], 'unread_notifications': 0}

    notes = (Notification.query.filter_by(user_id=current_user.id)
             .order_by(Notification.created_at.desc(), Notification.id.desc())
             .limit(8).all())
    unread = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return {'nav_notifications': notes, 'unread_notifications': unread}


@app.route('/admin/booking/new', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_new_booking():
    rooms = Room.query.order_by(Room.name).all()
    error = None
    conflict_link = None
    form = {'email': '', 'name': '', 'student_id': '',
            'room_name': request.args.get('room', '')}

    if request.method == 'POST':
        form['email'] = (request.form.get('email') or '').strip()
        form['name'] = (request.form.get('name') or '').strip()
        form['student_id'] = (request.form.get('student_id') or '').strip()
        form['room_name'] = request.form.get('room_name') or ''

        student = User.query.filter(User.email.ilike(form['email'])).first()
        room = Room.query.filter_by(name=form['room_name']).first()
        conflict = (booking_conflict(student.id, form['name'] or student.email)
                    if student is not None and not student.is_admin else None)

        if not form['name'] or not form['email']:
            error = "The student's name and email are both required."
        elif student is None:
            error = 'No account uses that email yet - ask the student to sign up first.'
        elif student.is_admin:
            error = 'That email belongs to a warden account, not a student.'
        elif conflict:
            error = conflict
            conflict_link = url_for('admin_bookings')
        elif room is None:
            error = 'Choose a room.'
        elif not room.is_available:
            error = f'{room.display_name} has no free bed right now.'
        else:
            db.session.add(Booking(user_id=student.id, room_name=room.name,
                                   status='awaiting_student',
                                   student_name=form['name'],
                                   student_id=form['student_id'] or None))
            notify(student.id,
                   f'The warden reserved {room.display_name} for you - sign in and confirm to activate it',
                   link=url_for('bookings'), kind='booking')
            db.session.flush()
            refresh_room_status(room)
            db.session.commit()
            flash(f'{room.display_name} reserved for {form["name"]} until they confirm')
            return redirect(url_for('admin_bookings'))

    return render_template('admin_new_booking.html', rooms=rooms, form=form,
                           error=error, conflict_link=conflict_link,
                           blocked_students=blocked_student_index())


@app.route('/booking/claim/<int:booking_id>', methods=['POST'])
@login_required
def claim_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    if booking.user_id != current_user.id:
        flash('That reservation is not yours.')
        return redirect(url_for('bookings'))
    if booking.status != 'awaiting_student':
        flash('That reservation is no longer waiting for you.')
        return redirect(url_for('bookings'))

    room = Room.query.filter_by(name=booking.room_name).first()
    label = room.display_name if room else booking.room_name

    # A student holds one bed at a time; moving rooms is a rebooking.
    if active_booking_for(current_user.id) is not None:
        flash('You already have an approved room - ask the warden to process a rebooking.')
        return redirect(url_for('bookings'))

    # The bed may have been taken while the reservation was waiting.
    if not room_has_free_bed(room, booking):
        flash(f'{label} is no longer free - please speak to the warden.')
        return redirect(url_for('bookings'))

    booking.status = 'active'
    current_user.selected_room = booking.room_name
    db.session.flush()
    if room:
        refresh_room_status(room)
    notify_admins(f'{current_user.email} confirmed the reservation for {label}',
                  link=url_for('admin_bookings'), kind='booking')
    db.session.commit()
    flash(f'{label} is now yours')
    return redirect(url_for('bookings'))


@app.route('/booking/decline/<int:booking_id>', methods=['POST'])
@login_required
def decline_reserved_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    if booking.user_id != current_user.id:
        flash('That reservation is not yours.')
        return redirect(url_for('bookings'))
    if booking.status != 'awaiting_student':
        flash('That reservation is no longer waiting for you.')
        return redirect(url_for('bookings'))

    room = Room.query.filter_by(name=booking.room_name).first()
    booking.status = 'cancelled'
    db.session.flush()
    if room:
        refresh_room_status(room)
    label = room.display_name if room else booking.room_name
    notify_admins(f'{current_user.email} declined the reservation for {label}',
                  link=url_for('admin_bookings'), kind='booking')
    db.session.commit()
    flash('Reservation declined')
    return redirect(url_for('bookings'))


@app.route('/make_admin/<int:user_id>')
def make_admin(user_id):
    role = UserRole(user_id=user_id, role="admin")
    db.session.add(role)
    db.session.commit()
    return "User is now admin"


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_default_rooms()

    app.run(debug=True)
