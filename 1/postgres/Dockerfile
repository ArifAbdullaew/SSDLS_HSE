FROM postgres:17

RUN apt-get update && apt-get install -y --no-install-recommends locales \
 && sed -i 's/# ru_RU.UTF-8 UTF-8/ru_RU.UTF-8 UTF-8/' /etc/locale.gen \
 && locale-gen ru_RU.UTF-8 && update-locale LANG=ru_RU.UTF-8 \
 && rm -rf /var/lib/apt/lists/*

ENV LANG=ru_RU.UTF-8 LC_ALL=ru_RU.UTF-8
ENV POSTGRES_DB=appdb
ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres
ENV POSTGRES_INITDB_ARGS="--encoding=UTF8 --locale=ru_RU.UTF-8"

COPY postgresql.conf /etc/postgresql/postgresql.conf
COPY 00-locale-scram.sh /docker-entrypoint-initdb.d/00-locale-scram.sh
COPY 10-init.sql        /docker-entrypoint-initdb.d/10-init.sql
