# https://hub.docker.com/r/centos/systemd/
FROM centos/systemd
LABEL maintainer="njeka0108@gmail.com"

RUN yum -y install gcc rpm-build build-essential python3.9 python3-pip python3.9-venv python3.9-dev nginx \
    && yum clean all \
    && mkdir -p /var/pyvenvs/ip2w \
    && python3.9 -m venv /var/pyvenvs/ip2w \
    && /var/pyvenvs/ip2w/bin/pip3.9 install --upgrade pip \
    && /var/pyvenvs/ip2w/bin/pip3.9 install uwsgi

COPY ./ip2w-0.0.1-1.noarch.rpm /tmp/

RUN rpm -ihv /tmp/ip2w-0.0.1-1.noarch.rpm \
    && systemctl enable nginx.service \
    && systemctl enable ip2w.service

EXPOSE 80
CMD ["/usr/sbin/init"]

# docker build --rm --no-cache -t centos/systemd/ip2w .
# docker run --privileged --name dcsip2w -v /sys/fs/cgroup:/sys/fs/cgroup:ro -p 8003:80 -d centos/systemd/ip2w