#!/usr/bin/env python3
"""Create admin user for Minerva Intelligence Platform"""

import sys
from sqlalchemy import create_engine, text
from passlib.context import CryptContext

# Password hasher
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database URL
import os
DB_URL = os.getenv("DATABASE_URL", "postgresql://minerva:MinervaDB2024@localhost:5432/minerva_db").replace("+asyncpg", "")

def main():
    print("🚀 Creating admin user for Minerva...")

    try:
        # Create engine
        engine = create_engine(DB_URL)

        with engine.connect() as conn:
            # Create ENUMs (check if exists first)
            print("Creating ENUM types...")
            conn.execute(text("""
                DO $$ BEGIN
                    CREATE TYPE userrole AS ENUM ('admin', 'power', 'analyst', 'viewer');
                EXCEPTION
                    WHEN duplicate_object THEN null;
                END $$;
            """))
            conn.execute(text("""
                DO $$ BEGIN
                    CREATE TYPE indexaccesslevel AS ENUM ('full', 'read', 'write', 'none');
                EXCEPTION
                    WHEN duplicate_object THEN null;
                END $$;
            """))
            conn.commit()

            # Create users table
            print("Creating users table...")
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    hashed_password VARCHAR(255) NOT NULL,
                    full_name VARCHAR(255),
                    role userrole NOT NULL DEFAULT 'viewer',
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """))
            conn.commit()

            # Hash password
            print("Hashing password...")
            hashed_password = pwd_context.hash("admin123")

            # Insert admin user
            print("Creating admin user...")
            result = conn.execute(text("""
                INSERT INTO users (username, email, hashed_password, full_name, role, is_active)
                VALUES (:username, :email, :password, :fullname, CAST(:role AS userrole), :active)
                ON CONFLICT (username) DO UPDATE SET
                    email = EXCLUDED.email,
                    full_name = EXCLUDED.full_name,
                    role = EXCLUDED.role,
                    updated_at = NOW()
                RETURNING id, username, email, role
            """), {
                "username": "admin",
                "email": "admin@minerva.local",
                "password": hashed_password,
                "fullname": "Administrator",
                "role": "admin",
                "active": True
            })

            conn.commit()

            user = result.fetchone()
            print("\n✅ Admin user created successfully!")
            print(f"   ID: {user[0]}")
            print(f"   Username: {user[1]}")
            print(f"   Email: {user[2]}")
            print(f"   Role: {user[3]}")
            print(f"\n🔑 Login credentials:")
            print(f"   Username: admin")
            print(f"   Password: admin123")
            print(f"\n🌐 Access Minerva at: http://localhost:8001")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
