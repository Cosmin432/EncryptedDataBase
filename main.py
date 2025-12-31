from DBManager import *
from KeyGenerator import *
db = Database()
password = db.get_user_password("test_user")
generator = KeyGenerator(db)
generator.test_key_generation()
db.close()