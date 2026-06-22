# --- build stage ---
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* .npmrc* ./
# --legacy-peer-deps: @vitejs/plugin-react's peer range lags behind Vite 8 (works at runtime).
RUN npm install --legacy-peer-deps
COPY . .
RUN npm run build

# --- serve stage ---
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
