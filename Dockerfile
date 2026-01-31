FROM node:22-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source and build
COPY tsconfig.json ./
COPY src/ ./src/
COPY dashboard/ ./dashboard/

# Install dev deps for build, then build, then prune
RUN npm install && npm run build && npm prune --production

# Expose port
EXPOSE 3847

# Run the HTTP server (dashboard)
CMD ["node", "dist/http-server.js"]
