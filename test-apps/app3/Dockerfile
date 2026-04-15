FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y build-essential libpng-dev

WORKDIR /app
COPY . /app

RUN make

CMD ["./app"]
