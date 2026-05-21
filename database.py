"""
সহজবন্ধু — Database Setup (SQLite)
Tables: users, listings, messages, sectors, applications
"""

import sqlite3
import hashlib
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "sahajbondhu.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def init_db():
    conn = get_db()
    c = conn.cursor()

    # ── USERS ──────────────────────────────────────────────
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        email       TEXT UNIQUE NOT NULL,
        phone       TEXT,
        password    TEXT NOT NULL,
        district    TEXT,
        bio         TEXT,
        role        TEXT DEFAULT 'user',          -- user | admin
        verified    INTEGER DEFAULT 0,
        avatar      TEXT,
        created_at  TEXT DEFAULT (datetime('now')),
        updated_at  TEXT DEFAULT (datetime('now'))
    )
    """)

    # ── SECTORS ────────────────────────────────────────────
    c.execute("""
    CREATE TABLE IF NOT EXISTS sectors (
        id    INTEGER PRIMARY KEY AUTOINCREMENT,
        name  TEXT UNIQUE NOT NULL,
        icon  TEXT,
        slug  TEXT UNIQUE NOT NULL
    )
    """)

    # ── LISTINGS (partner ads) ──────────────────────────────
    c.execute("""
    CREATE TABLE IF NOT EXISTS listings (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        sector_id     INTEGER REFERENCES sectors(id),
        title         TEXT NOT NULL,
        description   TEXT NOT NULL,
        investment_min INTEGER,
        investment_max INTEGER,
        district      TEXT,
        partner_type  TEXT,   -- investor | skills | both
        commitment    TEXT,   -- fulltime | parttime
        status        TEXT DEFAULT 'active',  -- active | closed | draft
        views         INTEGER DEFAULT 0,
        created_at    TEXT DEFAULT (datetime('now')),
        updated_at    TEXT DEFAULT (datetime('now'))
    )
    """)

    # ── APPLICATIONS ────────────────────────────────────────
    c.execute("""
    CREATE TABLE IF NOT EXISTS applications (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        listing_id  INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        applicant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        message     TEXT,
        status      TEXT DEFAULT 'pending',   -- pending | accepted | rejected
        created_at  TEXT DEFAULT (datetime('now')),
        UNIQUE(listing_id, applicant_id)
    )
    """)

    # ── MESSAGES ────────────────────────────────────────────
    c.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        content     TEXT NOT NULL,
        read        INTEGER DEFAULT 0,
        created_at  TEXT DEFAULT (datetime('now'))
    )
    """)

    # ── SAVED LISTINGS ──────────────────────────────────────
    c.execute("""
    CREATE TABLE IF NOT EXISTS saved_listings (
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        saved_at   TEXT DEFAULT (datetime('now')),
        PRIMARY KEY(user_id, listing_id)
    )
    """)

    conn.commit()

    # ── SEED SECTORS ────────────────────────────────────────
    sectors = [
        ("ই-কমার্স",            "🛒", "ecommerce"),
        ("ফুড ও রেস্টুরেন্ট",   "🍽️", "food"),
        ("ফ্যাশন ও গার্মেন্টস", "👗", "fashion"),
        ("প্রযুক্তি ও আইটি",    "💻", "tech"),
        ("রিয়েল এস্টেট",        "🏗️", "realestate"),
        ("কৃষি ও অ্যাগ্রো",     "🌾", "agro"),
        ("শিক্ষা ও প্রশিক্ষণ",  "📚", "education"),
        ("স্বাস্থ্যসেবা",        "🏥", "health"),
        ("পরিবহন ও লজিস্টিক্স", "🚗", "transport"),
        ("ট্যুরিজম ও হোটেল",    "✈️", "tourism"),
    ]
    c.executemany(
        "INSERT OR IGNORE INTO sectors(name, icon, slug) VALUES(?,?,?)",
        sectors
    )

    # ── SEED DEMO USERS ─────────────────────────────────────
    demo_users = [
        ("মোঃ তারেক হোসেন", "tarek@demo.com", "01711000001", hash_password("demo123"), "ঢাকা", "ই-কমার্স উদ্যোক্তা", 1),
        ("ফারহানা আক্তার",   "farhana@demo.com","01711000002", hash_password("demo123"), "চট্টগ্রাম", "ফুড বিজনেস উদ্যোক্তা", 0),
        ("আলী হোসেন সরকার", "ali@demo.com",    "01711000003", hash_password("demo123"), "রাজশাহী", "কৃষি উদ্যোক্তা", 1),
    ]
    for u in demo_users:
        c.execute("""
            INSERT OR IGNORE INTO users(name,email,phone,password,district,bio,verified)
            VALUES(?,?,?,?,?,?,?)
        """, u)

    conn.commit()

    # ── SEED DEMO LISTINGS ──────────────────────────────────
    c.execute("SELECT id FROM users WHERE email='tarek@demo.com'")
    u1 = c.fetchone()
    c.execute("SELECT id FROM users WHERE email='farhana@demo.com'")
    u2 = c.fetchone()
    c.execute("SELECT id FROM users WHERE email='ali@demo.com'")
    u3 = c.fetchone()
    c.execute("SELECT id FROM sectors WHERE slug='ecommerce'")
    s_ec = c.fetchone()
    c.execute("SELECT id FROM sectors WHERE slug='food'")
    s_food = c.fetchone()
    c.execute("SELECT id FROM sectors WHERE slug='agro'")
    s_agro = c.fetchone()

    if u1 and s_ec:
        c.execute("""
            INSERT OR IGNORE INTO listings(user_id,sector_id,title,description,
              investment_min,investment_max,district,partner_type,commitment)
            VALUES(?,?,?,?,?,?,?,?,?)
        """, (
            u1["id"], s_ec["id"],
            "অনলাইন গ্রোসারি ডেলিভারি স্টার্টআপে পার্টনার দরকার",
            "আমার কাছে টেক টিম ও প্ল্যাটফর্ম আছে। একজন অপারেশনস পার্টনার দরকার যিনি সাপ্লাই চেইন সামলাবেন।",
            1000000, 2000000, "ঢাকা", "skills", "fulltime"
        ))
    if u2 and s_food:
        c.execute("""
            INSERT OR IGNORE INTO listings(user_id,sector_id,title,description,
              investment_min,investment_max,district,partner_type,commitment)
            VALUES(?,?,?,?,?,?,?,?,?)
        """, (
            u2["id"], s_food["id"],
            "হোমমেড ফুড ব্র্যান্ডে বিনিয়োগকারী পার্টনার খুঁজছি",
            "রান্নার রেসিপি ও ব্র্যান্ড তৈরি আছে। মার্কেটিং ও ফান্ডিং পার্টনার দরকার।",
            300000, 500000, "চট্টগ্রাম", "investor", "parttime"
        ))
    if u3 and s_agro:
        c.execute("""
            INSERT OR IGNORE INTO listings(user_id,sector_id,title,description,
              investment_min,investment_max,district,partner_type,commitment)
            VALUES(?,?,?,?,?,?,?,?,?)
        """, (
            u3["id"], s_agro["id"],
            "জৈব সবজি এক্সপোর্ট ব্যবসায় পার্টনার দরকার",
            "৫০ বিঘা জমি ও চাষের অভিজ্ঞতা আছে। ইউরোপে এক্সপোর্টের জন্য একজন বিজনেস ডেভেলপমেন্ট পার্টনার খুঁজছি।",
            3000000, 5000000, "রাজশাহী", "both", "fulltime"
        ))

    conn.commit()
    conn.close()
    print("✅ Database initialized: sahajbondhu.db")


if __name__ == "__main__":
    init_db()
