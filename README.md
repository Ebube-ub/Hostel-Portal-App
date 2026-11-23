# Hostel-Portal-App

A Flask + SQLite hostel room booking portal. Students sign up, pick a room and
report maintenance issues; wardens get an admin dashboard for rooms, bookings
and complaints.

## Requirements

- Python 3.10+ (developed against 3.12)

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python seed.py --email warden@school.edu    # tables, rooms, admin account
flask --app app run
```

Then open http://127.0.0.1:5000.

`seed.py` prints a generated admin password the first time it creates the
account - note it down. Re-running it is safe. Without `--email` it only
creates the rooms.

## Rooms and capacity

Rooms have a type and a bed capacity: a **private** room holds one student, a
**shared** room holds two. A shared room stays bookable until both beds are
taken, and it is only marked `occupied` once it is full.

The seed creates six private rooms (101-104, 107, 109) and three shared rooms
(105, 106, 108) - twelve beds in total. `Room.occupied_beds`, `free_beds` and
`is_available` are derived from active bookings, so the room list, the admin
tables and the occupancy stats all follow from the same data.

## Project layout

```
app.py                      routes, models and forms
seed.py                     database seeding (rooms + admin account)
templates/                  Jinja templates, base.html plus one per page
assets/scss/main.scss       stylesheet source
static/css/main.css         compiled stylesheet (committed, see below)
static/img/                 images
instance/hostel.db          SQLite database, created on first run (git-ignored)
```

## Editing styles

`static/css/main.css` is generated from `assets/scss/main.scss` and is committed
so a fresh clone works without a Sass toolchain. After changing the SCSS,
recompile it:

```bash
python -c "import sass; open('static/css/main.css','w').write(sass.compile(filename='assets/scss/main.scss'))"
```

## Configuration

| Setting      | Default                       | Notes                                  |
| ------------ | ----------------------------- | -------------------------------------- |
| `SECRET_KEY` | development fallback          | Set this to a random value in any real deployment |

```bash
SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')" flask --app app run
```

The database path comes from `SQLALCHEMY_DATABASE_URI` in `app.py`; Flask stores
relative SQLite paths under `instance/`.
