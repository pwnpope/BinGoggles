FROM ubuntu:latest

ARG HOST_UID
ARG HOST_GID

RUN apt-get update -y && apt-get upgrade -y && \
    apt-get install -y \
    	curl \
	gcc=4:13.2.0-7ubuntu1 \
	make

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

RUN echo "${HOST_UID}:${HOST_GID}"

RUN id -u ${HOST_UID} >/dev/null 2>&1 || \
    (getent group ${HOST_GID} || groupadd -g ${HOST_GID} builder) && \
    useradd -m -u ${HOST_UID} -g ${HOST_GID} builder


USER ${HOST_UID}:${HOST_GID}

WORKDIR /src

CMD ["ls -la"]
