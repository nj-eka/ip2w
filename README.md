# ip2w
ip to weather - uWSGI daemon (service) tutorial project. 
## Overview:
This is implementation of **uWSGI*** daemon for Ubuntu (CentOS 7/8 optional), which provides ip details (via *ipinfo.io*) and weather (current and forecast - using *openweathermap.org* api) information for given ip address.
ATTENTION: you need to register on these sites and use your own api keys (as described below).

**Service should:**
- Use external open api: 
    - IP details: https://ipinfo.io/developers (via https://github.com/ipinfo/python IPinfo Python Client Library)
    - Current weather: https://openweathermap.org/current
    - Current and forcast (in "onecall"): https://openweathermap.org/api/one-call-api
- Run as systemd uwsgi service
- Nginx should proxy requests to this service using uwsgi protocol
- Service should be built into deb-package (rpm optional)
- All of the above should work in docker container.

## Requirements:
+ OS: `Ubuntu 20.* (CentOS 7/8)`
+ Depends: `systemd, nginx, python3.9, python3-pip, python3.9-venv`
+ Python libraries:
`
ipinfo==4.2.0
invoke==1.5.0
requests==2.25.1
GitPython==3.1.17
uwsgi==2.0.19.1
`

## Instalation:
```sh
git clone https://github.com/nj-eka/ip2w.git
cd ip2w
pip install -r requirements.txt
# edit file: package_config/ip2w.env
# to define your keys:
# IPINFO_KEY={123456789ABCDE} <- ipinfo.io key
# IP2W_KEY={123456789ABCDE} <- openweathermap.org key
invoke build_deb docker_build -t ubuntu docker-run -t ubuntu
# to run simple functional tests
invoke run-tests -t ubuntu
```
use the following config files if needed:
* *ip2w.env* - to set up environment variables for ip2w uwsgi service 
* *ip2w.uwsgi.ini* - app/uwsgi configuration settings (app logging, app methods and uwsgi ini) 
* *ip2w.service* - systemd ip2w service
* *ip2w.nginx.conf* - nginx proxy requests settings 
* *invoke.yaml* - invoke tasks settings

## Usage:
Examples:
```
curl 'http://localhost:8002/ip2w/79.165.43.252' # == http://localhost:8002/ip2w/weather?ip=79.165.43.252'
curl 'http://localhost:8002/ip2w/weather?ip=79.165.43.252'
curl 'http://localhost:8002/ip2w/weather?ip=79.165.43.252&lang=ru''
curl 'http://localhost:8002/ip2w/weather?ip=79.165.43.252&lang=ru&mode=html''
curl 'http://localhost:8002/ip2w/weather?lat=37.615&lon=55.752&lang=ru'
curl 'http://localhost:8002/ip2w/onecall?ip=79.165.43.252'
curl 'http://localhost:8002/ip2w/onecall?lat=33.333&lon=55.555&exclude=daily&lang=de'
curl 'http://localhost:8002/ip2w/ipinfo?ip=79.165.43.252'
```
