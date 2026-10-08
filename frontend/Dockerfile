# Multi-stage production build for CloudScope Frontend
FROM node:22-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production server
FROM nginxinc/nginx-unprivileged:alpine

# Remove default nginx welcome page
USER root
RUN rm -rf /usr/share/nginx/html/*
USER nginx

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
