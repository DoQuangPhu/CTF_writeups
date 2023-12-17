FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive
ENV LC_CTYPE=C.UTF-8

# Update sources.list
# RUN sed -i 's/archive.ubuntu.com\|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

RUN useradd -m -s /bin/bash pwn1
WORKDIR /home/pwn1

RUN chown root:root /home/pwn1
RUN chmod 755 /home/pwn1


RUN apt-get update -y && apt-get install -y \
    build-essential \
    socat \
    netcat

COPY pwn1 /home/pwn1
COPY flag /home/pwn1

RUN chown root:root /home/pwn1/pwn1
RUN chown root:root /home/pwn1/flag 
RUN chmod 111 /home/pwn1/pwn1
RUN chmod 444 /home/pwn1/flag  


USER pwn1
ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/pwn1/pwn1,stderr"]
EXPOSE 1337
