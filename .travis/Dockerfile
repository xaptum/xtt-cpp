FROM ubuntu:xenial

RUN apt-get -qq update \
    && apt-get -qq install -y --no-install-recommends \
       build-essential \
       wget \
       clang \
       g++ \
       ca-certificates \
       && rm -rf /var/lib/apt/lists/* \
       && wget -q https://cmake.org/files/v3.11/cmake-3.11.4-Linux-x86_64.tar.gz \
       && tar -xzf cmake-3.11.4-Linux-x86_64.tar.gz \
       && cp -fR cmake-3.11.4-Linux-x86_64/* /usr \
       && rm -rf cmake-3.11.4-Linux-x86_64 \
       && rm cmake-3.11.4-Linux-x86_64.tar.gz

#INSTALLS BOOST
RUN wget http://downloads.sourceforge.net/project/boost/boost/1.66.0/boost_1_66_0.tar.gz \
  && tar xfz boost_1_66_0.tar.gz \
  && rm boost_1_66_0.tar.gz \
  && cd boost_1_66_0 \
  && ./bootstrap.sh --prefix=/usr/local --with-libraries=system,thread \
  && ./b2 install \
  && cd ..


RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys c615bfaa7fe1b4ca
RUN echo "deb http://dl.bintray.com/xaptum/deb stretch main" > /etc/apt/sources.list.d/xaptum.list
RUN apt-get update && apt-get install -y --no-install-recommends apt-utils
RUN apt-get install libsodium18
RUN apt-get install libsodium-dev
RUN apt-get install libamcl4
RUN apt-get install libamcl-dev
RUN apt-get install libxaptum-tpm0
RUN apt-get install libxaptum-tpm-dev
RUN apt-get install libecdaa0
RUN apt-get install libecdaa-dev
RUN apt-get install libecdaa-tpm0
RUN apt-get install libecdaa-tpm-dev
RUN apt-get install libxtt0
RUN apt-get install libxtt-dev
