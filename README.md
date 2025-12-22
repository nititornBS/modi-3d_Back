# Modi 3D Backend

Express.js backend with PostgreSQL for authentication.

## Features

- User registration (email/password)
- User login with JWT authentication
- Google OAuth login
- Protected routes
- PostgreSQL database integration

## Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment Variables

Create a `.env` file in the root directory:

```env
PORT=3000

DB_HOST=localhost
DB_PORT=5432
DB_NAME=Modi3d
DB_USER=postgres
DB_PASSWORD=your_password_here

JWT_SECRET=your_super_secret_jwt_key_change_this_in_production

# Google OAuth (for Google login)
GOOGLE_CLIENT_ID=your_google_client_id_here
```

### 3. Set Up PostgreSQL Database

1. Make sure PostgreSQL is installed and running
2. Create a database:
   ```sql
   CREATE DATABASE Modi3d;
   ```
3. The application will automatically create the `users` table on first run

### 4. Run the Server

```bash
# Development mode (with nodemon)
npm run dev

# Production mode
npm start
```

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register a new user
  - Body: `{ "username": "user123", "email": "user@example.com", "password": "password123" }`
  - Returns: JWT token and user info

- `POST /api/auth/login` - Login user
  - Body: `{ "email": "user@example.com", "password": "password123" }`
  - Returns: JWT token and user info

- `POST /api/auth/google` - Login with Google
  - Body: `{ "idToken": "google_id_token_from_frontend" }`
  - Returns: JWT token and user info
  - Note: Frontend should send the Google ID token obtained from Google Sign-In

- `GET /api/auth/me` - Get current user info (requires token)
  - Headers: `Authorization: Bearer <token>`
  - Returns: User info

### Protected Routes

- `GET /api/protected` - Example protected route
  - Headers: `Authorization: Bearer <token>`
  - Returns: Protected content

## Usage Example

### Register a new user:
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"password123"}'
```

### Login:
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

### Google Login:
```bash
curl -X POST http://localhost:3000/api/auth/google \
  -H "Content-Type: application/json" \
  -d '{"idToken":"GOOGLE_ID_TOKEN_FROM_FRONTEND"}'
```

### Access protected route:
```bash
curl -X GET http://localhost:3000/api/protected \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable Google+ API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client ID"
5. Set application type to "Web application"
6. Add authorized JavaScript origins (e.g., `http://localhost:3000`)
7. Add authorized redirect URIs
8. Copy the Client ID and add it to your `.env` file as `GOOGLE_CLIENT_ID`

## Project Structure

```
.
├── config/
│   └── database.js      # PostgreSQL connection and initialization
├── middleware/
│   └── auth.js          # JWT authentication middleware
├── routes/
│   └── auth.js          # Authentication routes
├── server.js             # Main server file
├── package.json
└── README.md
```
