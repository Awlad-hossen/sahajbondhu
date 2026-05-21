"""
সহজবন্ধু — REST API (Flask + SQLite + JWT)
Base URL: http://localhost:5000/api
"""

import os
import hashlib
import json
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, g
import jwt

from database import get_db, hash_password, init_db

# ── CONFIG ──────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "sahajbondhu-secret-2025-bd")
JWT_EXPIRY_HOURS = 24

app = Flask(__name__)

# Manual CORS (no flask-cors needed)
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
    return response

@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        from flask import Response
        r = Response()
        r.headers["Access-Control-Allow-Origin"] = "*"
        r.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        r.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
        return r, 200


# ── JWT HELPERS ─────────────────────────────────────────────────
def make_token(user_id: int, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        token = auth[7:]
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            g.user_id = data["sub"]
            g.role = data.get("role", "user")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return wrapper


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        require_auth(lambda: None)()
        if getattr(g, "role", "") != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return wrapper


def row_to_dict(row):
    return dict(row) if row else None


# ════════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/api/auth/register", methods=["POST"])
def register():
    """POST /api/auth/register — নতুন ব্যবহারকারী নিবন্ধন"""
    body = request.get_json() or {}
    name     = (body.get("name") or "").strip()
    email    = (body.get("email") or "").strip().lower()
    phone    = (body.get("phone") or "").strip()
    password = (body.get("password") or "")
    district = (body.get("district") or "").strip()
    bio      = (body.get("bio") or "").strip()

    if not name or not email or not password:
        return jsonify({"error": "name, email ও password আবশ্যক"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password কমপক্ষে ৬ অক্ষর হতে হবে"}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        db.close()
        return jsonify({"error": "এই ইমেইল দিয়ে আগেই নিবন্ধন হয়েছে"}), 409

    db.execute(
        "INSERT INTO users(name,email,phone,password,district,bio) VALUES(?,?,?,?,?,?)",
        (name, email, phone, hash_password(password), district, bio)
    )
    db.commit()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    db.close()

    token = make_token(user["id"], user["role"])
    return jsonify({
        "message": "নিবন্ধন সফল হয়েছে",
        "token": token,
        "user": {
            "id": user["id"], "name": user["name"],
            "email": user["email"], "district": user["district"],
            "verified": bool(user["verified"]), "role": user["role"]
        }
    }), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    """POST /api/auth/login — লগইন"""
    body = request.get_json() or {}
    email    = (body.get("email") or "").strip().lower()
    password = (body.get("password") or "")

    if not email or not password:
        return jsonify({"error": "email ও password আবশ্যক"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    db.close()

    if not user or user["password"] != hash_password(password):
        return jsonify({"error": "ইমেইল বা পাসওয়ার্ড ভুল"}), 401

    token = make_token(user["id"], user["role"])
    return jsonify({
        "message": "লগইন সফল",
        "token": token,
        "user": {
            "id": user["id"], "name": user["name"],
            "email": user["email"], "district": user["district"],
            "verified": bool(user["verified"]), "role": user["role"]
        }
    })


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def me():
    """GET /api/auth/me — নিজের প্রোফাইল দেখুন"""
    db = get_db()
    user = db.execute(
        "SELECT id,name,email,phone,district,bio,verified,role,avatar,created_at FROM users WHERE id=?",
        (g.user_id,)
    ).fetchone()
    db.close()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(row_to_dict(user))


# ════════════════════════════════════════════════════════════════
#  USER ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/api/users/<int:uid>", methods=["GET"])
def get_user(uid):
    """GET /api/users/:id — পাবলিক প্রোফাইল"""
    db = get_db()
    user = db.execute(
        "SELECT id,name,district,bio,verified,avatar,created_at FROM users WHERE id=?", (uid,)
    ).fetchone()
    db.close()
    if not user:
        return jsonify({"error": "User পাওয়া যায়নি"}), 404
    return jsonify(row_to_dict(user))


@app.route("/api/users/me", methods=["PUT"])
@require_auth
def update_profile():
    """PUT /api/users/me — প্রোফাইল আপডেট"""
    body = request.get_json() or {}
    allowed = ["name", "phone", "district", "bio"]
    updates = {k: body[k] for k in allowed if k in body}
    if not updates:
        return jsonify({"error": "আপডেট করার কিছু নেই"}), 400

    sets = ", ".join(f"{k}=?" for k in updates)
    vals = list(updates.values()) + [g.user_id]
    db = get_db()
    db.execute(f"UPDATE users SET {sets}, updated_at=datetime('now') WHERE id=?", vals)
    db.commit()
    db.close()
    return jsonify({"message": "প্রোফাইল আপডেট হয়েছে"})


# ════════════════════════════════════════════════════════════════
#  SECTOR ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/api/sectors", methods=["GET"])
def get_sectors():
    """GET /api/sectors — সব সেক্টর ও লিস্টিং কাউন্ট"""
    db = get_db()
    rows = db.execute("""
        SELECT s.id, s.name, s.icon, s.slug,
               COUNT(l.id) AS listing_count
        FROM sectors s
        LEFT JOIN listings l ON l.sector_id = s.id AND l.status='active'
        GROUP BY s.id
        ORDER BY listing_count DESC
    """).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ════════════════════════════════════════════════════════════════
#  LISTING ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/api/listings", methods=["GET"])
def get_listings():
    """
    GET /api/listings
    Query params: sector, district, partner_type, commitment,
                  min, max, search, page, limit
    """
    sector       = request.args.get("sector")
    district     = request.args.get("district")
    partner_type = request.args.get("partner_type")
    commitment   = request.args.get("commitment")
    inv_min      = request.args.get("min", type=int)
    inv_max      = request.args.get("max", type=int)
    search       = request.args.get("search", "")
    page         = request.args.get("page", 1, type=int)
    limit        = min(request.args.get("limit", 10, type=int), 50)
    offset       = (page - 1) * limit

    where = ["l.status='active'"]
    params = []

    if sector:
        where.append("s.slug=?"); params.append(sector)
    if district:
        where.append("l.district=?"); params.append(district)
    if partner_type:
        where.append("l.partner_type=?"); params.append(partner_type)
    if commitment:
        where.append("l.commitment=?"); params.append(commitment)
    if inv_min:
        where.append("l.investment_max >= ?"); params.append(inv_min)
    if inv_max:
        where.append("l.investment_min <= ?"); params.append(inv_max)
    if search:
        where.append("(l.title LIKE ? OR l.description LIKE ?)")
        params += [f"%{search}%", f"%{search}%"]

    where_sql = "WHERE " + " AND ".join(where) if where else ""

    db = get_db()
    total = db.execute(
        f"SELECT COUNT(*) FROM listings l LEFT JOIN sectors s ON s.id=l.sector_id {where_sql}",
        params
    ).fetchone()[0]

    rows = db.execute(f"""
        SELECT l.*, u.name AS user_name, u.district AS user_district,
               u.verified AS user_verified, u.avatar AS user_avatar,
               s.name AS sector_name, s.icon AS sector_icon, s.slug AS sector_slug
        FROM listings l
        LEFT JOIN users   u ON u.id = l.user_id
        LEFT JOIN sectors s ON s.id = l.sector_id
        {where_sql}
        ORDER BY l.created_at DESC
        LIMIT ? OFFSET ?
    """, params + [limit, offset]).fetchall()
    db.close()

    return jsonify({
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit,
        "results": [dict(r) for r in rows]
    })


@app.route("/api/listings/<int:lid>", methods=["GET"])
def get_listing(lid):
    """GET /api/listings/:id — একটি লিস্টিং দেখুন (views +1)"""
    db = get_db()
    db.execute("UPDATE listings SET views=views+1 WHERE id=?", (lid,))
    db.commit()
    row = db.execute("""
        SELECT l.*, u.name AS user_name, u.district AS user_district,
               u.verified AS user_verified, u.bio AS user_bio, u.phone AS user_phone,
               s.name AS sector_name, s.icon AS sector_icon
        FROM listings l
        LEFT JOIN users   u ON u.id=l.user_id
        LEFT JOIN sectors s ON s.id=l.sector_id
        WHERE l.id=?
    """, (lid,)).fetchone()
    db.close()
    if not row:
        return jsonify({"error": "Listing পাওয়া যায়নি"}), 404
    return jsonify(dict(row))


@app.route("/api/listings", methods=["POST"])
@require_auth
def create_listing():
    """POST /api/listings — নতুন লিস্টিং তৈরি করুন"""
    body = request.get_json() or {}
    required = ["title", "description"]
    for f in required:
        if not body.get(f):
            return jsonify({"error": f"'{f}' আবশ্যক"}), 400

    db = get_db()
    # Resolve sector
    sector_id = None
    if body.get("sector_slug"):
        sec = db.execute("SELECT id FROM sectors WHERE slug=?", (body["sector_slug"],)).fetchone()
        if sec:
            sector_id = sec["id"]

    db.execute("""
        INSERT INTO listings(user_id,sector_id,title,description,
          investment_min,investment_max,district,partner_type,commitment)
        VALUES(?,?,?,?,?,?,?,?,?)
    """, (
        g.user_id, sector_id,
        body["title"], body["description"],
        body.get("investment_min"), body.get("investment_max"),
        body.get("district"), body.get("partner_type"), body.get("commitment")
    ))
    db.commit()
    lid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.close()
    return jsonify({"message": "লিস্টিং তৈরি হয়েছে", "id": lid}), 201


@app.route("/api/listings/<int:lid>", methods=["PUT"])
@require_auth
def update_listing(lid):
    """PUT /api/listings/:id — লিস্টিং আপডেট (মালিক only)"""
    db = get_db()
    listing = db.execute("SELECT user_id FROM listings WHERE id=?", (lid,)).fetchone()
    if not listing:
        db.close(); return jsonify({"error": "Listing পাওয়া যায়নি"}), 404
    if listing["user_id"] != g.user_id and g.role != "admin":
        db.close(); return jsonify({"error": "আপনার অনুমতি নেই"}), 403

    body = request.get_json() or {}
    allowed = ["title","description","investment_min","investment_max",
               "district","partner_type","commitment","status"]
    updates = {k: body[k] for k in allowed if k in body}
    if not updates:
        db.close(); return jsonify({"error": "কিছু আপডেট করুন"}), 400

    sets = ", ".join(f"{k}=?" for k in updates)
    vals = list(updates.values()) + [lid]
    db.execute(f"UPDATE listings SET {sets}, updated_at=datetime('now') WHERE id=?", vals)
    db.commit(); db.close()
    return jsonify({"message": "লিস্টিং আপডেট হয়েছে"})


@app.route("/api/listings/<int:lid>", methods=["DELETE"])
@require_auth
def delete_listing(lid):
    """DELETE /api/listings/:id"""
    db = get_db()
    listing = db.execute("SELECT user_id FROM listings WHERE id=?", (lid,)).fetchone()
    if not listing:
        db.close(); return jsonify({"error": "Listing পাওয়া যায়নি"}), 404
    if listing["user_id"] != g.user_id and g.role != "admin":
        db.close(); return jsonify({"error": "আপনার অনুমতি নেই"}), 403

    db.execute("DELETE FROM listings WHERE id=?", (lid,))
    db.commit(); db.close()
    return jsonify({"message": "লিস্টিং মুছে ফেলা হয়েছে"})


@app.route("/api/listings/my", methods=["GET"])
@require_auth
def my_listings():
    """GET /api/listings/my — আপনার সব লিস্টিং"""
    db = get_db()
    rows = db.execute("""
        SELECT l.*, s.name AS sector_name, s.icon AS sector_icon
        FROM listings l
        LEFT JOIN sectors s ON s.id=l.sector_id
        WHERE l.user_id=?
        ORDER BY l.created_at DESC
    """, (g.user_id,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ── SAVE/UNSAVE ─────────────────────────────────────────────────
@app.route("/api/listings/<int:lid>/save", methods=["POST"])
@require_auth
def save_listing(lid):
    db = get_db()
    try:
        db.execute("INSERT INTO saved_listings(user_id,listing_id) VALUES(?,?)", (g.user_id, lid))
        db.commit()
        msg = "Listing সেভ হয়েছে"
    except Exception:
        db.execute("DELETE FROM saved_listings WHERE user_id=? AND listing_id=?", (g.user_id, lid))
        db.commit()
        msg = "Listing আনসেভ হয়েছে"
    db.close()
    return jsonify({"message": msg})


@app.route("/api/listings/saved", methods=["GET"])
@require_auth
def saved_listings():
    db = get_db()
    rows = db.execute("""
        SELECT l.*, s.name AS sector_name, s.icon AS sector_icon,
               u.name AS user_name, u.verified AS user_verified
        FROM saved_listings sl
        JOIN listings l ON l.id = sl.listing_id
        LEFT JOIN sectors s ON s.id = l.sector_id
        LEFT JOIN users   u ON u.id = l.user_id
        WHERE sl.user_id=?
        ORDER BY sl.saved_at DESC
    """, (g.user_id,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ════════════════════════════════════════════════════════════════
#  APPLICATION ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/api/listings/<int:lid>/apply", methods=["POST"])
@require_auth
def apply(lid):
    """POST /api/listings/:id/apply — পার্টনারশিপের জন্য আবেদন"""
    body = request.get_json() or {}
    message = body.get("message", "").strip()

    db = get_db()
    listing = db.execute("SELECT user_id FROM listings WHERE id=? AND status='active'", (lid,)).fetchone()
    if not listing:
        db.close(); return jsonify({"error": "Listing পাওয়া যায়নি বা বন্ধ"}), 404
    if listing["user_id"] == g.user_id:
        db.close(); return jsonify({"error": "নিজের লিস্টিংয়ে আবেদন করা যাবে না"}), 400

    try:
        db.execute(
            "INSERT INTO applications(listing_id,applicant_id,message) VALUES(?,?,?)",
            (lid, g.user_id, message)
        )
        db.commit()
        aid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.close()
        return jsonify({"message": "আবেদন সফল হয়েছে", "id": aid}), 201
    except Exception:
        db.close()
        return jsonify({"error": "আপনি ইতোমধ্যে আবেদন করেছেন"}), 409


@app.route("/api/listings/<int:lid>/applications", methods=["GET"])
@require_auth
def listing_applications(lid):
    """GET /api/listings/:id/applications — লিস্টিং মালিক দেখুন"""
    db = get_db()
    listing = db.execute("SELECT user_id FROM listings WHERE id=?", (lid,)).fetchone()
    if not listing or (listing["user_id"] != g.user_id and g.role != "admin"):
        db.close(); return jsonify({"error": "অনুমতি নেই"}), 403

    rows = db.execute("""
        SELECT a.*, u.name AS applicant_name, u.district AS applicant_district,
               u.bio AS applicant_bio, u.verified AS applicant_verified
        FROM applications a
        JOIN users u ON u.id = a.applicant_id
        WHERE a.listing_id=?
        ORDER BY a.created_at DESC
    """, (lid,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/applications/<int:aid>/status", methods=["PATCH"])
@require_auth
def update_application(aid):
    """PATCH /api/applications/:id/status — accepted | rejected"""
    body = request.get_json() or {}
    status = body.get("status")
    if status not in ("accepted", "rejected"):
        return jsonify({"error": "status হবে: accepted অথবা rejected"}), 400

    db = get_db()
    app_row = db.execute("""
        SELECT a.id, l.user_id AS owner_id FROM applications a
        JOIN listings l ON l.id=a.listing_id WHERE a.id=?
    """, (aid,)).fetchone()
    if not app_row or (app_row["owner_id"] != g.user_id and g.role != "admin"):
        db.close(); return jsonify({"error": "অনুমতি নেই"}), 403

    db.execute("UPDATE applications SET status=? WHERE id=?", (status, aid))
    db.commit(); db.close()
    return jsonify({"message": f"আবেদন {status} করা হয়েছে"})


@app.route("/api/applications/my", methods=["GET"])
@require_auth
def my_applications():
    """GET /api/applications/my — আমার আবেদনসমূহ"""
    db = get_db()
    rows = db.execute("""
        SELECT a.*, l.title AS listing_title, l.district AS listing_district,
               s.name AS sector_name, s.icon AS sector_icon
        FROM applications a
        JOIN listings l ON l.id=a.listing_id
        LEFT JOIN sectors s ON s.id=l.sector_id
        WHERE a.applicant_id=?
        ORDER BY a.created_at DESC
    """, (g.user_id,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ════════════════════════════════════════════════════════════════
#  MESSAGE ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/api/messages/<int:other_id>", methods=["GET"])
@require_auth
def get_messages(other_id):
    """GET /api/messages/:userId — দুইজনের মধ্যে কথোপকথন"""
    db = get_db()
    # Mark received as read
    db.execute("""
        UPDATE messages SET read=1
        WHERE sender_id=? AND receiver_id=? AND read=0
    """, (other_id, g.user_id))
    db.commit()

    rows = db.execute("""
        SELECT m.*, u.name AS sender_name FROM messages m
        JOIN users u ON u.id=m.sender_id
        WHERE (m.sender_id=? AND m.receiver_id=?)
           OR (m.sender_id=? AND m.receiver_id=?)
        ORDER BY m.created_at ASC
    """, (g.user_id, other_id, other_id, g.user_id)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/messages/<int:other_id>", methods=["POST"])
@require_auth
def send_message(other_id):
    """POST /api/messages/:userId — বার্তা পাঠান"""
    body = request.get_json() or {}
    content = (body.get("content") or "").strip()
    if not content:
        return jsonify({"error": "বার্তা খালি হতে পারবে না"}), 400

    db = get_db()
    other = db.execute("SELECT id FROM users WHERE id=?", (other_id,)).fetchone()
    if not other:
        db.close(); return jsonify({"error": "User পাওয়া যায়নি"}), 404

    db.execute(
        "INSERT INTO messages(sender_id,receiver_id,content) VALUES(?,?,?)",
        (g.user_id, other_id, content)
    )
    db.commit()
    mid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.close()
    return jsonify({"message": "বার্তা পাঠানো হয়েছে", "id": mid}), 201


@app.route("/api/messages/inbox", methods=["GET"])
@require_auth
def inbox():
    """GET /api/messages/inbox — সব কথোপকথন (latest per user)"""
    db = get_db()
    rows = db.execute("""
        SELECT u.id, u.name, u.verified, u.avatar,
               m.content AS last_message, m.created_at AS last_at,
               SUM(CASE WHEN m.read=0 AND m.receiver_id=? THEN 1 ELSE 0 END) AS unread
        FROM messages m
        JOIN users u ON u.id = CASE
            WHEN m.sender_id=? THEN m.receiver_id ELSE m.sender_id END
        WHERE m.sender_id=? OR m.receiver_id=?
        GROUP BY u.id
        ORDER BY last_at DESC
    """, (g.user_id, g.user_id, g.user_id, g.user_id)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ════════════════════════════════════════════════════════════════
#  STATS / ADMIN
# ════════════════════════════════════════════════════════════════

@app.route("/api/stats", methods=["GET"])
def stats():
    """GET /api/stats — প্ল্যাটফর্ম পরিসংখ্যান"""
    db = get_db()
    users    = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    listings = db.execute("SELECT COUNT(*) FROM listings WHERE status='active'").fetchone()[0]
    apps     = db.execute("SELECT COUNT(*) FROM applications WHERE status='accepted'").fetchone()[0]
    msgs     = db.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    db.close()
    return jsonify({
        "total_users": users,
        "active_listings": listings,
        "successful_partnerships": apps,
        "total_messages": msgs
    })


@app.route("/api/admin/users", methods=["GET"])
@require_auth
def admin_users():
    """GET /api/admin/users — সব ব্যবহারকারী (admin only)"""
    if g.role != "admin":
        return jsonify({"error": "Admin access required"}), 403
    db = get_db()
    rows = db.execute(
        "SELECT id,name,email,phone,district,verified,role,created_at FROM users ORDER BY created_at DESC"
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/verify/<int:uid>", methods=["PATCH"])
@require_auth
def admin_verify(uid):
    """PATCH /api/admin/verify/:id — ব্যবহারকারী যাচাই করুন"""
    if g.role != "admin":
        return jsonify({"error": "Admin access required"}), 403
    db = get_db()
    db.execute("UPDATE users SET verified=1 WHERE id=?", (uid,))
    db.commit(); db.close()
    return jsonify({"message": "ব্যবহারকারী যাচাই করা হয়েছে"})


# ── HEALTH CHECK ────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "OK", "app": "সহজবন্ধু API", "version": "1.0.0"})


# ── ERROR HANDLERS ──────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route পাওয়া যায়নি"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "সার্ভার সমস্যা হয়েছে"}), 500


# ── MAIN ────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("\n🚀 সহজবন্ধু API চালু হচ্ছে...")
    print("📍 http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
