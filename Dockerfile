FROM node:20-alpine AS base
WORKDIR /app

ENV PYTHON=python3 \
    CXXFLAGS="-std=c++20"

COPY package.json package-lock.json ./
RUN apk add --no-cache --virtual .build-deps python3 make g++ \
    && npm ci \
    && apk del .build-deps

COPY src ./src
COPY client ./client
COPY agents.md README.md ./

ENV NODE_ENV=production \
    APP_PORT=3000 \
    OAUTH_PORT=4000 \
    APP_BASE_URL=http://localhost:3000 \
    OAUTH_BASE_URL=http://localhost:4000 \
    CLIENT_ID=task-app \
    CLIENT_NAME="Task Manager"

EXPOSE 3000 4000

CMD ["npm", "start"]
