import psycopg2
from psycopg2 import *

class Database:
    def __init__(self):
        self.conn = psycopg2.connect(
            host="localhost",
            port=5432,
            user="postgres",
            password="admin",
            database="encrypteddb"
        )

    def get_user_password(self, username):
        with self.conn.cursor() as cursor:
            cursor.execute(
                "SELECT password_hash FROM my_schema.users WHERE username=%s",
                (username,)
            )
            result = cursor.fetchone()
            if result:
                return result[0]
            return None
    def close(self):
        self.conn.close()