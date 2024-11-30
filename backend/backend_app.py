import json
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required
)
import os

# Automatically set the absolute path
DATA_FILE = os.path.join(os.path.dirname(__file__), "../data/post_data.json")

def load_posts():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w") as fileobj:
            json.dump([], fileobj)  # Initialize with an empty list if file doesn't exist
    with open(DATA_FILE, "r") as fileobj:
        return json.load(fileobj)

def save_posts(posts):
    with open(DATA_FILE, "w") as fileobj1:
        json.dump(posts, fileobj1, indent=4)  # Save formatted JSON

# Load posts at the start
POSTS = load_posts()

# Flask App Initialization
app = Flask(__name__)
limiter = Limiter(app=app, key_func=get_remote_address)
CORS(app)
bcrypt = Bcrypt(app)

# JWT Configuration
app.config["JWT_SECRET_KEY"] = "secret"
jwt = JWTManager(app)
USERS = {}
@app.before_request
def log_request_info():
    print(f"Request Path: {request.path}")
    print(f"Query Parameters: {request.args}")
# User Registration Endpoint
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username in USERS:
        return jsonify({"error": "User already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    USERS[username] = hashed_password
    return jsonify({"message": "User registered successfully"}), 201

# User Login Endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    stored_password = USERS.get(username)
    if not stored_password or not bcrypt.check_password_hash(stored_password, password):
        return jsonify({"error": "Invalid username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify({"access_token": access_token}), 200

# Validate Post Data
def validate_post_data(new_post):
    return "title" in new_post and "content" in new_post

# Get or Create Posts
@app.route('/api/posts', methods=['GET', 'POST'])
@limiter.limit("10/minute")
def posts():
    global POSTS
    if request.method == 'GET':
        # Sorting
        sort_field = request.args.get('sort', '').lower()
        sort_direction = request.args.get('direction', 'asc').lower()
        if sort_field in ['title', 'content']:
            reverse = sort_direction == 'desc'
            sorted_posts = sorted(POSTS, key=lambda x: x[sort_field].lower(), reverse=reverse)
            return jsonify(sorted_posts), 200
        return jsonify(POSTS), 200

    elif request.method == 'POST':
        new_post = request.get_json()
        if not validate_post_data(new_post):
            return jsonify({"error": "Invalid post data"}), 400

        # Add New Post
        new_id = max([post['id'] for post in POSTS], default=0) + 1
        new_post['id'] = new_id
        POSTS.append(new_post)
        save_posts(POSTS)  # Save to file
        return jsonify(new_post), 201

# Find Post by ID
def find_post_by_id(post_id):
    return next((post for post in POSTS if post['id'] == post_id), None)

# Update a Post
@app.route('/api/posts/<int:id>', methods=['PUT'])
@jwt_required()
def update_post(id):
    global POSTS
    post = find_post_by_id(id)
    if post is None:
        return jsonify({"error": "Post not found"}), 404

    new_data = request.get_json()
    post.update(new_data)
    save_posts(POSTS)  # Save updated data
    return jsonify(post), 200

# Delete a Post
@app.route('/api/posts/<int:id>', methods=['DELETE'])
@limiter.limit("1/minute")
@jwt_required()
def delete_post(id):
    global POSTS
    post = find_post_by_id(id)
    if post is None:
        return jsonify({"error": "Post not found"}), 404

    POSTS.remove(post)
    save_posts(POSTS)  # Save changes
    return jsonify(post), 200

# Search Posts
@app.route("/api/posts/search", methods=['GET'])
def search_post():
    title_query = request.args.get('title', '').lower()
    content_query = request.args.get('content', '').lower()

    filtered_posts = [
        post for post in POSTS
        if (title_query and title_query in post['title'].lower()) or
           (content_query and content_query in post['content'].lower())
    ]

    return jsonify(filtered_posts), 200

# Paginate Posts
@app.route('/api/posts-paginated', methods=['GET'])
def posts_pagination():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 3))
    start_index = (page - 1) * limit
    end_index = start_index + limit

    paginated_posts = POSTS[start_index:end_index]
    return jsonify(paginated_posts), 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5002, debug=True)
