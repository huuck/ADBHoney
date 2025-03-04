FROM python:3.12-alpine3.21

RUN apk update && apk add git

RUN git clone https://github.com/huuck/ADBHoney

WORKDIR ADBHoney
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
