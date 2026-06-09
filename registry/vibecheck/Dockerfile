FROM node:20-alpine

RUN apk add --no-cache clamav clamav-daemon freshclam git bash

WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY . .

RUN mkdir -p /var/lib/clamav && chown clamav:clamav /var/lib/clamav
RUN freshclam --quiet || true

EXPOSE 3210

CMD ["sh", "-c", "freshclam --quiet || true && node server.js"]
