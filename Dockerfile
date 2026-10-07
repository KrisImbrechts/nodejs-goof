# FROM node:6-stretch
FROM node:18.13.0

RUN mkdir /usr/src/goof
RUN mkdir /tmp/extracted_files
COPY . /usr/src/goof
WORKDIR /usr/src/goof

RUN npm update
RUN npm install
RUN npm install selfsigned
EXPOSE 3001
EXPOSE 3443
EXPOSE 9229
ENTRYPOINT ["npm", "start"]
