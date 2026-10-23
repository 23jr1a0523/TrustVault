
from database import get_db_connection

username = input("Enter your registered username: ").strip()

connection = get_db_connection()

try:
    user = connection.execute(
        "SELECT id, username, role FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if user is None:
        print("User not found. Please check your registered username.")
    else:
        connection.execute(
            "UPDATE users SET role = 'admin' WHERE id = ?",
            (user["id"],)
        )
        connection.commit()
        print(f"{username} is now an admin.")

finally:
    connection.close()
