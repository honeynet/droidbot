# A docker image, where DroidBot interacts with Droidbox instance.
# https://github.com/lynnlyc/droidbot
# the dockerized Droidbox instance was copied from https://github.com/aikinci/droidbox
FROM ubuntu:14.04
MAINTAINER ali@ikinci.info

WORKDIR /opt

ENV LC_ALL C
ENV DEBIAN_FRONTEND noninteractive
ENV JAVA_HOME /usr/lib/jvm/java-7-openjdk-amd64/
ENV ANDROID_HOME /opt/android-sdk-linux
ENV ANDROID_SDK_HOME /opt/android-sdk-linux
ENV PATH ${PATH}:$JAVA_HOME/bin:${ANDROID_HOME}/tools:${ANDROID_HOME}/platform-tools
ENV ROOTPASSWORD droidbox

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get install -y --no-install-recommends openjdk-7-jdk apt-utils curl expect python-tk python-matplotlib nano git openssh-server telnet libc6:i386 libncurses5:i386 libstdc++6:i386 bsdmainutils patch

# RUN curl -O http://dl.google.com/android/android-sdk_r24.3.3-linux.tgz && \
#    tar xfz android-sdk_r24.3.3-linux.tgz && \
#    rm -f android-sdk_r24.3.3-linux.tgz
COPY docker_downloads/android-sdk_r24.3.3-linux.tgz /opt/
RUN tar xfz android-sdk_r24.3.3-linux.tgz && \
    rm -f android-sdk_r24.3.3-linux.tgz

# RUN curl -O http://droidbox.googlecode.com/files/DroidBox411RC.tar.gz && \
#    tar xfz DroidBox411RC.tar.gz && \
#    rm -f DroidBox411RC.tar.gz
COPY docker_downloads/DroidBox411RC.tar.gz /opt/
RUN tar xfz DroidBox411RC.tar.gz && \
    rm -f DroidBox411RC.tar.gz

# accept-licenses was taken from https://github.com/embarkmobile/android-sdk-installer and is Licensed under the MIT License.
ADD docker/accept-licenses /build/
RUN expect /build/accept-licenses "android update sdk --no-ui --all --filter platform-tool,system-image,android-16" "android-sdk-license-5be876d5" && \
    echo "\n"| android create avd -n droidbox -t 1 -d 2

# ssh setup
RUN sed  's/PermitRootLogin without-password/PermitRootLogin yes/g' /etc/ssh/sshd_config -i && \
    echo "root:$ROOTPASSWORD" | chpasswd ;

# fastdroid-vnc was taken from https://code.google.com/p/fastdroid-vnc/ it is GPLv2 licensed
ADD docker/fastdroid-vnc /build/
ADD docker/install-fastdroid-vnc.sh /build/
RUN /build/install-fastdroid-vnc.sh
ADD docker/run.sh /build/
#ADD docker/droidbox.py.patch /build/
#RUN cd /opt/DroidBox_4.1.1/scripts && patch < /build/droidbox.py.patch

# Add DroitBot
RUN apt-get install -y --no-install-recommends python-setuptools python-pip
ADD . /opt/DroidBot
RUN easy_install -q --upgrade androidviewclient
RUN pip install -q /opt/DroidBot

CMD ["NONE"]

ENTRYPOINT ["/build/run.sh"]
