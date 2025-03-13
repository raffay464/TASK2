FROM postgres:latest
ENV POSTGRES_DB=usersdb
ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres
COPY init.sql /docker-entrypoint-initdb.d/
