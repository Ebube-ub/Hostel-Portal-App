"""Seed the hostel database.

Creates the tables, the nine rooms (only when the rooms table is empty) and,
optionally, an admin account:

    python seed.py
    python seed.py --email warden@school.edu
    python seed.py --email warden@school.edu --password "choose-something"

When no password is given one is generated and printed once. The script is safe
to re-run: rooms are only inserted into an empty table, existing databases get
the room_type/capacity columns added, and the admin role is only added when the
account does not already have it.
"""

import argparse
import secrets

from sqlalchemy import inspect, text

from app import (
    ROOM_CAPACITY,
    ROOM_LAYOUT,
    Room,
    User,
    UserRole,
    app,
    bcrypt,
    create_default_rooms,
    db,
    refresh_room_status,
)


def ensure_room_columns():
    """Add room_type/capacity to databases created before rooms had a type."""
    if "room" not in inspect(db.engine).get_table_names():
        return False

    columns = {column["name"] for column in inspect(db.engine).get_columns("room")}
    added = False

    if "room_type" not in columns:
        db.session.execute(
            text("ALTER TABLE room ADD COLUMN room_type VARCHAR(20) NOT NULL DEFAULT 'private'")
        )
        added = True

    if "capacity" not in columns:
        db.session.execute(
            text("ALTER TABLE room ADD COLUMN capacity INTEGER NOT NULL DEFAULT 1")
        )
        added = True

    db.session.commit()
    return added


def backfill_room_types():
    """Apply the room layout to rooms that predate the room_type column."""
    changed = 0
    for name, room_type in ROOM_LAYOUT:
        room = Room.query.filter_by(name=name).first()
        if room is None:
            continue

        capacity = ROOM_CAPACITY[room_type]
        if room.room_type != room_type or room.capacity != capacity:
            room.room_type = room_type
            room.capacity = capacity
            changed += 1

    db.session.commit()
    if changed:
        print(f"Updated the type and capacity of {changed} rooms.")


def refresh_statuses():
    """Recalculate available/occupied from the active bookings."""
    for room in Room.query.all():
        refresh_room_status(room)
    db.session.commit()


def seed_admin(email, password):
    user = User.query.filter_by(email=email).first()
    generated = False

    if user is None:
        if not password:
            password = secrets.token_urlsafe(9)
            generated = True
        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(email=email, password=hashed)
        db.session.add(user)
        db.session.commit()
        print(f"Created account {email}")
    else:
        print(f"Account {email} already exists, reusing it.")

    if UserRole.query.filter_by(user_id=user.id, role="admin").first() is None:
        db.session.add(UserRole(user_id=user.id, role="admin"))
        db.session.commit()
        print(f"Granted the admin role to {email}")
    else:
        print(f"{email} is already an admin.")

    if generated:
        print("")
        print(f"Generated password: {password}")
        print("Write it down now - it is not stored anywhere.")


def main():
    parser = argparse.ArgumentParser(description="Seed the hostel database.")
    parser.add_argument("--email", help="account to create or promote to admin")
    parser.add_argument("--password", help="password for a newly created admin")
    args = parser.parse_args()

    with app.app_context():
        db.create_all()

        if ensure_room_columns():
            print("Added the room_type/capacity columns to the room table.")

        created = create_default_rooms()
        if created:
            print(f"Created {created} rooms: {', '.join(name for name, _ in ROOM_LAYOUT)}")
        else:
            print(f"Rooms already present ({Room.query.count()}), skipping.")

        backfill_room_types()
        refresh_statuses()

        if args.email:
            seed_admin(args.email, args.password)
        else:
            print("No --email given, so no admin account was created.")


if __name__ == "__main__":
    main()
