# Imagem com app_a e app_b compilados em C.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
	gcc libc6-dev make \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /opt/mission
COPY app_a.c app_b.c Makefile.apps ./
RUN make -f Makefile.apps

ENV PEER_IP=
CMD ["/opt/mission/app_a"]
