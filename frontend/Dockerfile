FROM node:20-alpine

WORKDIR /app

# Copy package files dulu (biar npm install di-cache)
COPY package*.json ./

# Install semua dependencies
RUN npm install

# Copy source (akan di-override oleh bind mount di dev mode)
COPY . .

EXPOSE 3000

# Default: production build + serve
# Di docker-compose dev: override dengan "npm run dev"
CMD ["sh", "-c", "npm run build && npx serve -s dist -l 3000"]
