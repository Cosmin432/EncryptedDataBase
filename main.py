from DBManager import *
from KeyGenerator import *

db = Database()
generator = KeyGenerator(db)

# Generate and store keys for test_user
user_id = "550e8400-e29b-41d4-a716-446655440000"
password = "password123"

key_id = generator.generate_and_store_keys(user_id, password)

if key_id:
    print(f"\n✅ Phase 2 Complete! Key ID: {key_id}")
else:
    print("\n❌ Phase 2 Failed")

db.close()