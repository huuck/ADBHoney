FROM python:2.7-alpine3.9

RUN apk update && apk add git

RUN git clone https://github.com/pieterbork/ADBHoney.git

WORKDIR ADBHoney
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
