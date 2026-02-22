# Persistent Deployment Guide

## Problem
Current Vercel deployment uses `/tmp` storage which resets on cold starts, causing user registrations to be lost.

## Solutions

### Option 1: Use External Database (Recommended)
1. **Setup Database**:
   - PostgreSQL (recommended): Create free account at [Supabase](https://supabase.com) or [Neon](https://neon.tech)
   - MongoDB: Create free account at [MongoDB Atlas](https://mongodb.com/atlas)

2. **Update Environment Variables**:
   ```bash
   # For PostgreSQL
   DATABASE_URL=postgresql://username:password@host:port/database
   
   # For MongoDB  
   MONGODB_URI=mongodb://username:password@host:port/database
   
   JWT_SECRET=your-super-secret-jwt-key-change-this
   ```

3. **Deploy to Vercel**:
   ```bash
   vercel --prod
   ```

### Option 2: Use Railway/Render with SQLite
1. **Deploy to Railway**:
   ```bash
   # Install Railway CLI
   npm install -g @railway/cli
   
   # Login and deploy
   railway login
   railway init
   railway up
   ```

2. **Deploy to Render**:
   - Connect your GitHub repo to [Render](https://render.com)
   - Choose "Web Service"
   - Set build command: `npm install`
   - Set start command: `npm start`

### Option 3: Self-host with Docker
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3847
CMD ["npm", "start"]
```

```bash
# Build and run
docker build -t postmeter .
docker run -p 3847:3847 -v $(pwd)/data:/app/data postmeter
```

## Environment Variables Required
- `DATABASE_URL` or `MONGODB_URI` (for external DB)
- `JWT_SECRET` (for secure authentication)
- `NODE_ENV=production` (optional)

## Testing
After deployment:
1. Register a new user
2. Logout and login again
3. Create workspace and collections
4. Wait 10+ minutes (for cold start on serverless)
5. Login again - data should persist
