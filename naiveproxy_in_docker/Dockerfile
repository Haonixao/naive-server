FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV CCACHE_MAXSIZE=200M
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH=${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools

RUN apt-get update && apt-get install -y \
    git curl wget unzip tar nano \
    ninja-build pkg-config ccache bubblewrap \
    python3 python3-pip openjdk-21-jdk \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p ${ANDROID_HOME}/cmdline-tools \
    && curl -o /tmp/cmdline-tools.zip https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip \
    && unzip -q /tmp/cmdline-tools.zip -d /tmp \
    && mv /tmp/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest \
    && rm /tmp/cmdline-tools.zip \
    && yes | sdkmanager --licenses \
    && sdkmanager "platform-tools" "platforms;android-36" "build-tools;36.0.0"

RUN git clone --depth 1 https://github.com/Haonixao/naiveproxy /naiveproxy

WORKDIR /naiveproxy

CMD ["/bin/bash"]