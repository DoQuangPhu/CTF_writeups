FROM ubuntu:22.04 

RUN useradd -ms /bin/bash pwn
WORKDIR /home/pwn

RUN apt-get update -y
RUN apt-get install socat -y

ADD zone_object /home/pwn
ADD flag /home/pwn
ADD libzone.so /home/pwn

RUN chmod 4 /home/pwn/flag
RUN chmod 5 /home/pwn/zone_object
RUN chmod 5 /home/pwn/libzone.so
ENV LD_LIBRARY_PATH=/home/pwn:$LD_LIBRARY_PATH
USER pwn

EXPOSE 2006

ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:2006,reuseaddr,fork EXEC:/home/pwn/zone_object,stderr"]