# Build stage
FROM hugomods/hugo:exts AS builder

WORKDIR /src

# Copy site files
COPY . .

# Build the site (disable git info since .git is not in build context)
RUN hugo --minify --enableGitInfo=false

# Production stage
FROM nginx:alpine

# Copy built site from builder
COPY --from=builder /src/public /usr/share/nginx/html

# Copy nginx config (optional, using default for now)
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
