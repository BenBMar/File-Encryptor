# --- Stage 1: Build ---
FROM node:18-alpine AS builder

WORKDIR /app

# Copy only dependency files first for caching
COPY package.json package-lock.json* ./
RUN npm ci --silent

# NOW copy the rest of the source code needed for the build
COPY . .
RUN node build.js

# --- Stage 2: Production Server ---
FROM nginx:alpine

# Create directories and assign permissions for non-root user (101 is the nginx user)
RUN mkdir -p /var/cache/nginx/client_temp \
             /var/log/nginx \
             /usr/share/nginx/html/lib && \
    touch /var/run/nginx.pid /var/log/nginx/error.log /var/log/nginx/access.log && \
    chown -R 101:101 /var/cache/nginx \
                     /var/log/nginx \
                     /var/run/nginx.pid \
                     /usr/share/nginx/html && \
    rm -rf /usr/share/nginx/html/* /var/cache/apk/* /tmp/*

# Copy built artifacts from builder
COPY --from=builder /app/lib/ /usr/share/nginx/html/lib/
COPY index.html styles.css app.js /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080

USER 101

CMD ["nginx", "-g", "daemon off;"]
