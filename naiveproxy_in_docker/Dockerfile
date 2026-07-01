FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV CCACHE_MAXSIZE=200M

RUN apt-get update && apt-get install -y \
    git curl wget unzip tar nano \
    ninja-build pkg-config ccache bubblewrap \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/Haonixao/naiveproxy /naiveproxy

WORKDIR /naiveproxy

CMD ["/bin/bash"]