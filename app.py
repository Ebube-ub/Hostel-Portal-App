from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_scss import Scss
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_bcrypt import Bcrypt
from functools import wraps


app = Flask(__name__)
Scss(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hostel.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    selected_room = db.Column(db.String(10))  # e.g., Room101
    complaint = db.Column(db.String(200), unique=True, nullable=True)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    current_occupant_email = db.Column(db.String(150))
    room_name = db.Column(db.String(50), nullable=False)
    check_in = db.Column(db.DateTime, default=db.func.now())
    status = db.Column(db.String(20), default='active')  # active, cancelled, completed

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    status = db.Column(db.String(20), default='available')
    current_occupant_email= db.Column(db.String(150))


class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)

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



@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None

    if True: #form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('You were successfully logged in')
                return redirect(url_for('dashboard'))
                
            else:
                flash('Invalid username or password')
                error = 'Invalid username or password'
    return render_template('login.html', form=form, error=error, from_signup=True)



@app.route('/dashboard', methods=['GET', 'POST'])  
@login_required  
def dashboard():
    rooms = Room.query.all()  # Fetch all rooms  
    # Get list of room names already selected by some user
    # Turn rooms into a dictionary like:
    # room_data["Room101"].status → “available”
    room_data = {room.name: room for room in rooms}
    taken_rooms = [u.selected_room for u in User.query.filter(User.selected_room.isnot(None)).all()]  

    error = None  
    if request.method == 'POST':  
        selected_room = request.form.get('room_name')  
        # If room is taken and it’s not already their own selected room
        if selected_room in taken_rooms and selected_room != current_user.selected_room:  
            error = "Sorry, that room is already taken!"  
        else:  
            current_user.selected_room = selected_room  # assign room to user  
            # Update room status
            room = Room.query.filter_by(name=selected_room).first()
            if room:
                room.status = 'occupied'
                room.current_occupant_email = current_user.email
            
            # Create booking record
            new_booking = Booking(
                user_id=current_user.id,
                current_occupant_email=current_user.email,
                room_name=selected_room,
                status='active'
            )
            db.session.add(new_booking)
            
            db.session.commit()
            flash('Room successfully picked')
            return redirect(url_for('dashboard'))  

    # Render dashboard passing user, rooms, taken list, error if any
    return render_template('dashboard.html', user=current_user, rooms=rooms, taken_rooms=taken_rooms, error=error, room_data=room_data)  





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


@app.route('/select_room/<room_number>')
@login_required
def select_room(room_number):
    current_user.selected_room = room_number
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/cancel_selection', methods=['POST'])
@login_required
def cancel_selection():
    # Update room status
    room = Room.query.filter_by(name=current_user.selected_room).first()
    if room:
        room.status = 'available'
        room.current_occupant_email = None
    # Update booking status
    booking = Booking.query.filter_by(user_id=current_user.id, room_name=current_user.selected_room, status='active').first()
    if booking:
        db.session.delete(booking)
    current_user.selected_room = None
    db.session.commit()                # Save changes to the database
    flash('Booking canceled')
    return redirect(url_for('dashboard'))

@app.route('/bookings', methods=['GET', 'POST'])
@login_required
def bookings():
    form = ComplaintForm()
    if form.validate_on_submit():
        # Create new issue instead of storing on user
        new_issue = RoomIssue(
            email=current_user.email,
            room_name=current_user.selected_room,
            description=form.complaint.data,
            status='pending',
            priority='medium')
        db.session.add(new_issue)
        db.session.commit()
        flash('Complaint Submitted Successfully')
        return redirect(url_for('bookings'))
    # Get user's issues 
    user_issues = RoomIssue.query.filter_by(email=current_user.email)\
                             .order_by(RoomIssue.created_at.desc())\
                             .all()

    
    return render_template('bookings.html', form=form, issues=user_issues)


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
    """Calculate statistics for admin dashboard"""
    total_rooms = Room.query.count()
    
    # Room status counts
    available_rooms = Room.query.filter_by(status='available').count()
    occupied_rooms = Room.query.filter_by(status='occupied').count()
    maintenance_rooms = Room.query.filter_by(status='maintenance').count()
    reserved_rooms = Room.query.filter_by(status='reserved').count()
    
    # Occupancy rate
    occupancy_rate = (occupied_rooms / total_rooms * 100) if total_rooms > 0 else 0
    
    # Bookings
    active_bookings = Booking.query.filter_by(status='active').count()
    
    # Issues
    pending_issues = RoomIssue.query.filter_by(status='pending').count()
    
    return {
        'total_rooms': total_rooms,
        'available_rooms': available_rooms,
        'occupied_rooms': occupied_rooms,
        'maintenance_rooms': maintenance_rooms,
        'reserved_rooms': reserved_rooms,
        'occupancy_rate': round(occupancy_rate, 1),
        'active_bookings': active_bookings,
        'pending_issues': pending_issues
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
        
        # If set to maintenance/available, clear occupant
        if new_status in ['maintenance', 'available']:
            room.current_occupant_email = None
            # Also clear user's selected_room if they were in this room
            User.query.filter_by(selected_room=room.name).update({'selected_room': None})
        
        db.session.commit()
        flash(f'Room {room.name} status updated to {new_status}')
    
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
    if room:
        room.status = 'available'
        room.current_occupant_email = None
    
    # Clear user's selection
    user = User.query.get(booking.user_id)
    if user:
        user.selected_room = None
    
    db.session.commit()
    flash(f'Booking cancelled for {booking.room_name}')
    return redirect(url_for('admin_bookings'))


@app.route('/admin/issues')
@login_required
@admin_required
def admin_issues():
    issues = RoomIssue.query.filter_by(email=current_user.email).all()
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
    
    if new_status:
        issue.status = new_status
        if new_status == 'resolved':
            issue.resolved_at = db.func.now()
    
    if new_priority:
        issue.priority = new_priority
    
    db.session.commit()
    flash('Issue updated successfully')
    return redirect(url_for('admin_issues'))

@app.route('/make_admin/<int:user_id>')
def make_admin(user_id):
    role = UserRole(user_id=user_id, role="admin")
    db.session.add(role)
    db.session.commit()
    return "User is now admin"


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Only create rooms if table is empty
        if Room.query.count() == 0:
            room_list = [Room(name=f"Room{num}") for num in range(101, 110)]
            db.session.bulk_save_objects(room_list)
            db.session.commit()

    app.run(debug=True)

    
