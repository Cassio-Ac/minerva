# Frontend Dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application
COPY . .

# Expose port
EXPOSE 5173

# Run application
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
