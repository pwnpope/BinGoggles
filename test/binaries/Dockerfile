# ubuntu 24.04 latest @ 440dcf6a5640b2ae5c77724e68787a906afb8ddee98bf86db94eea8528c2c076
FROM ubuntu:440dcf6a5640b2ae5c77724e68787a906afb8ddee98bf86db94eea8528c2c076

RUN apt-get update -y && apt-get upgrade -y && \
    apt-get install -y \
     curl gcc make

ENV MUSL_VERSION=1.2.5
ENV PREFIX=/opt/musl

RUN curl -LO https://musl.libc.org/releases/musl-${MUSL_VERSION}.tar.gz && \
    tar -xzf musl-${MUSL_VERSION}.tar.gz && \
    cd musl-${MUSL_VERSION} && \
    ./configure --prefix=$PREFIX CC=gcc && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf musl-${MUSL_VERSION}*

ENV PATH=$PREFIX/bin:$PATH
ENV CC=musl-gcc

ARG HOST_UID=1000
ARG HOST_GID=1000

RUN id -u ${HOST_UID} >/dev/null 2>&1 || \
    (getent group ${HOST_GID} || groupadd -g ${HOST_GID} builder && \
     useradd -m -u ${HOST_UID} -g ${HOST_GID} builder)

USER ${HOST_UID}:${HOST_GID}

WORKDIR /src

CMD ["ls -la"]
