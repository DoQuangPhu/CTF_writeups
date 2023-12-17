FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive
ENV LC_CTYPE=C.UTF-8

# Update sources.list
# RUN sed -i 's/archive.ubuntu.com\|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

RUN useradd -m -s /bin/bash pwn2
WORKDIR /home/pwn2

RUN chown root:root /home/pwn2
RUN chmod 755 /home/pwn2

RUN apt-get update --fix-missing -y
RUN apt-get install -y apt-utils software-properties-common
RUN apt-get install -y build-essential \
        git \
        gdb \
        python3 python3-pip \
        strace \
        ltrace \
        socat \
        netcat \
        curl \
        wget \
        binutils \
        elfutils \
        file
    

RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)"    


COPY pwn2 /home/pwn2
COPY flag /home/pwn2
COPY ./ld-linux-x86-64.so.2 /home/pwn2 
COPY ./libc.so.6 /home/pwn2 

RUN chown root:root /home/pwn2/pwn2
RUN chown root:root /home/pwn2/flag 
RUN chmod 111 /home/pwn2/pwn2  
RUN chmod 444 /home/pwn2/flag  

USER pwn2
ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/pwn2/pwn2,stderr"]
EXPOSE 1337
