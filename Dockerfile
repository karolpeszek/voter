FROM ubuntu:22.04

VOLUME /pdfs

WORKDIR /voter

COPY package*.json ./

RUN apt-get update
RUN apt-get install software-properties-common -y
RUN /usr/bin/add-apt-repository ppa:saiarcot895/chromium-dev -y
RUN apt install -y gnupg curl

RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg
RUN gpg --no-default-keyring --keyring /usr/share/keyrings/nodesource.gpg --list-keys

RUN chmod a+r /usr/share/keyrings/nodesource.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x jammy main" | tee /etc/apt/sources.list.d/nodesource.list
RUN echo "deb-src [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x jammy main" | tee -a /etc/apt/sources.list.d/nodesource.list

RUN apt-get update

RUN apt upgrade -y
RUN apt-get install -y chromium-browser nodejs
RUN npm install -g npm
RUN /usr/bin/npm install

COPY . .

EXPOSE 5000

CMD ["/usr/bin/node", "/voter/index.js", "--prod"]
