# https://github.com/bdellegrazie/docker-ubuntu-systemd/blob/master/Dockerfile
FROM ubuntu:20.10
LABEL maintainer="njeka0108@gmail.com"

ENV container=docker

RUN sed -i 's/# deb/deb/g' /etc/apt/sources.list

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
    dbus systemd systemd-cron rsyslog iproute2 libpcre3 libpcre3-dev sudo bash ca-certificates gcc build-essential python3.9 python3-pip python3.9-venv python3.9-dev nginx && \
    apt-get clean && \
    rm -rf /usr/share/doc/* /usr/share/man/* /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN sed -i 's/^\(module(load="imklog")\)/#\1/' /etc/rsyslog.conf

RUN find /etc/systemd/system \
    /lib/systemd/system \
    -path '*.wants/*' \
    -not -name '*dbus*' \
    -not -name '*journald*' \
    -not -name '*systemd-tmpfiles*' \
    -not -name '*systemd-user-sessions*' \
    -exec rm \{} \;

RUN systemctl set-default multi-user.target
RUN systemctl mask dev-hugepages.mount sys-fs-fuse-connections.mount

VOLUME ["/sys/fs/cgroup", "/tmp", "/run", "/run/lock"]
STOPSIGNAL SIGRTMIN+3

COPY ./ip2w-0.1.deb .
RUN dpkg -i ip2w-0.1.deb

EXPOSE 80

CMD ["/sbin/init", "--log-target=journal"]
