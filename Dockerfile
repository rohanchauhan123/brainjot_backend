FROM node:20-slim

# Create non-root user before setting up the app
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install --production

COPY . .

# Hand ownership to appuser so the process can write uploads and sessions
RUN chown -R appuser:appgroup /usr/src/app

USER appuser

EXPOSE 3001
CMD [ "node", "server.js" ]
