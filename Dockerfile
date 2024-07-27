FROM node:alpine
WORKDIR /usr/app
COPY ./package.json ./
COPY ./package-lock.json ./
RUN npm install
COPY ./controllers ./controllers
COPY ./models ./models
COPY ./routes ./routes
COPY ./views ./views
COPY ./.env ./
COPY ./app.js ./
COPY ./auth.js ./
CMD ["npm", "start"]