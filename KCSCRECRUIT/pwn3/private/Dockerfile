FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive
ENV LC_CTYPE=C.UTF-8

# Update sources.list
# RUN sed -i 's/archive.ubuntu.com\|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

RUN useradd -m -s /bin/bash pwn3
WORKDIR /home/pwn3

RUN chown root:root /home/pwn3
RUN chmod 755 /home/pwn3


RUN apt-get update -y && apt-get install -y \
    build-essential \
    socat \
    netcat

COPY pwn3 /home/pwn3
COPY flag /home/pwn3

RUN chown root:root /home/pwn3/pwn3
RUN chown root:root /home/pwn3/flag 
RUN chmod 111 /home/pwn3/pwn3  
RUN chmod 444 /home/pwn3/flag  


USER pwn3
ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/pwn3/pwn3,stderr"]
EXPOSE 1337
