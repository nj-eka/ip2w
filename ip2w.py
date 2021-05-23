""" ip2w.py
    This is a simple tutorial uwsgi python application implementing service that provides various information for ip address:
    ip details iteself (ipinfo method)  and various weather information (wether, onecall) at geo location taken from ip address
"""
import os
import sys
import re
import time
import logging
import json
import pickle
import inspect
import collections as cs

from functools import wraps, partial
from pathlib import Path
from configparser import ConfigParser, ExtendedInterpolation
from http import HTTPStatus
from urllib.parse import unquote, urlparse, parse_qsl

import requests
# https://github.com/ipinfo/python
import ipinfo
# https://uwsgi-docs.readthedocs.io/en/latest/WSGIquickstart.html  https://readthedocs.org/projects/uwsgi-docs/downloads/pdf/latest/
import uwsgi  # pylint: disable=import-error

INI_FILE_NAME = 'ip2w.uwsgi.ini'  # usage: os.environ.get('IP2W_INI_FILE', str(Path(__file__).parent.resolve() / INI_FILE_NAME))
ENC, ESC = sys.getfilesystemencoding(), 'surrogateescape'
METHOD_CACHE_ID = 'cache_id'    # name of key in [app.api.{method}] section that enables uwsgi caching for {method}
METHOD_CACHE_EXPIRES = 'cache_expires'  #  -\\- set uwsgi caching time, if applicable for cache
DEFAULT_REQUEST_TIME_OUT = 4.0  # in s

CACHE_CFG_ID = "ip2w_cfg"  # CACHE_CFG_ID = os.environ.get('IP2W_CACHE_CFG_ID', CACHE_CFG_ID) ; should be ini independent since config cache is read BEFORE reading ini file.
# ini config dependent global settings
APP_ENC_HTML_DEFAULT = 'iso-8859-1'  # ENC
APP_HTTP_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
APP_DEFAULT_METHOD = 'weather'
APP_SERVER_NAME = 'ip2w'

def gmtime_string(timestamp: int = None, format_time: str = APP_HTTP_DATE_FORMAT):
    """Return [timestamp] as [format_time] GMT string. If [timestamp] is None then use current time."""
    return time.strftime(format_time, time.gmtime(timestamp))

def jpp(obj):
    """ Simple json pretty print (used for dict types here) """
    return json.dumps(obj, indent=2, sort_keys=True)

def wsgi_to_bytes(text: str) -> bytes:
    """ Encode string to bytes accoriding uwsgi specification """
    return text.encode(APP_ENC_HTML_DEFAULT)

def status_line(status: HTTPStatus) -> str:
    """ Return status line for HTTPStatus """
    return f'{status.value} {status.phrase}'

class HttpException(Exception):
    """Exception class for passing http status with some details."""
    def __init__(self, status: HTTPStatus = HTTPStatus.INTERNAL_SERVER_ERROR, details: str = None, exception: Exception = None):
        super().__init__()
        self.status: HTTPStatus = status
        self.details = details if details else str(exception)
        if not self.details and sys.exc_info()[1]:
            self.details = f'{sys.exc_info()[1]}'
        self._headers, self._content = None, None

    @property
    def status_line(self) -> str:
        """ status_line string """
        return status_line(self.status)

    @property
    def headers(self) -> dict:
        """ headers dict """
        if not self._headers:
            self._headers = {
                'Server': APP_SERVER_NAME,
                'Date': gmtime_string(),
                'Content-Type': f'application/json; charset={APP_ENC_HTML_DEFAULT}', #ENC
                'Content-Length': str(len(self.content)),
                'Connection': 'close',
            }
        return self._headers

    @property
    def content(self) -> bytes:
        """ content bytes """
        if not self._content:
            self._content = wsgi_to_bytes(
                    json.dumps({
                        'cod': self.status.value,
                        'message': f'{self.status.phrase} - {self.status.description}',
                        'details':  self.details,
                    })
            )
        return self._content

Response = cs.namedtuple('Response', ['status_line', 'headers', 'content'])

def cache_get(key: str, cache_id: str, strict: bool = True, default = None, logging_enable = True):
    """ Get value from uwsgi cache. Used for app config section settings only <- json serializable """
    logging.debug('Looking for [%s] in cache [%s]', key, cache_id)
    if uwsgi.cache_exists(key, cache_id):
        value = uwsgi.cache_get(key, cache_id)
        value = json.loads(value.decode())
        if logging_enable:
            logging.debug('cache [%s] -> %s : %s', cache_id, key, value)
        return value
    if strict:
        raise HttpException(details=f'Cache [{cache_id}]: {key} is missing')
    if logging_enable:
        logging.debug('Сache [%s] missed for [%s] DEFAULT value [%s] is used', cache_id, key, default)
    return default

def config_app(section: str = '', **kwargs):
    """ Return common cached application settings [app.{section}] """
    section = f'app.{section}' if section else 'app'
    return cache_get(section, CACHE_CFG_ID, **kwargs)

def config_method(method: str, **kwargs) -> dict:
    """ Return method's specific cached settings [app.api.{method}] """
    method_section = f'app.api.{method}'
    return cache_get(method_section, CACHE_CFG_ID, **kwargs)

def sub_ref2env(match_ref: re.Match, env: dict) -> str:
    ' ref -> env[ref] '
    ref = match_ref.group(1)
    return env[ref] if ref in env else match_ref.group(0)

rec_uwsgi_ref2env = re.compile(r'\$\((\w+)\)')

def expand_uwsgi_ref2env(text: str, env: dict, rec = rec_uwsgi_ref2env) -> str:
    ' $(ENV) -> env[ENV] '
    env = {k: v.decode() if isinstance(v, bytes) else str(v) for k, v in env.items() if isinstance(v, (str, int, bytes))}
    _sub_ref2env = partial(sub_ref2env, env = env)
    return rec.sub(_sub_ref2env, text)

def init(env):
    """ Initialize/cache application settings, set logging """
    logging_debugs = []  # buffer for debug loggging, since logger has not yet been initialized.
    global CACHE_CFG_ID  # pylint: disable=global-statement
    CACHE_CFG_ID = os.environ.get('IP2W_CACHE_CFG_ID', CACHE_CFG_ID)
    logging_debugs.append(f'{os.getuid()}:{os.getgid()}')
    logging_debugs.append(f'OS Environmets:\n{os.environ}\nUWSGI Environments:\n{env}')
    logging_debugs.append(f'Start init app using cache [{CACHE_CFG_ID=}]')
    try:
        if not uwsgi.cache_exists('app', CACHE_CFG_ID):  # If {app} section is present in cache, then everything else (app.*) is there too.
            cfg_fp = os.environ.get('IP2W_INI_FILE', str(Path(__file__).parent / "config" / INI_FILE_NAME))
            with open(cfg_fp) as cfg_f:
                cfg_text = cfg_f.read()
            cfg_text = os.path.expandvars(cfg_text)  # resolve $ENV | ${ENV} refs to os.environ
            cfg_text = expand_uwsgi_ref2env(cfg_text, env) # resolve $(ENV) refs to uwsgi env
            cfg_text = expand_uwsgi_ref2env(cfg_text, os.environ) # resolve $(ENV) refs to os.environ
            config = ConfigParser(interpolation=ExtendedInterpolation(), strict=False, allow_no_value=True)
            # use original case of key names
            config.optionxform = lambda option: option
            # # add section [wsgi.env] to resolve uwsgi refs ${wsgi.env:key}
            # config.read_dict({'wsgi.env': dict(filter(lambda item: type(item[1]) in [int, str], env.items()))})
            config.read_string(cfg_text)  # + resolve ${section:key} refs if [section] key exists else config[section].items() will throw exception
            for section in config:
                if section.startswith('app'):  # just filter uwsgi section
                    cfg_section = dict(config[section].items())  # actual interpolation takes place here throu internal calling to config.get(section, ...)
                    logging_debugs.append(f'cache [{CACHE_CFG_ID}] <- {section}: {jpp(cfg_section)} ')
                    # https://readthedocs.org/projects/uwsgi-docs/downloads/pdf/latest/ :
                    # The expires argument (default to 0 for disabled) is the number of seconds after the object is no more valid
                    # (and will be removed by the cache sweeper when purge_lru is not set...)
                    uwsgi.cache_set(section, json.dumps(cfg_section).encode(), 0, CACHE_CFG_ID)
                    logging_debugs.append(f'uwsgi.cache_exists({section}, {CACHE_CFG_ID}) = {uwsgi.cache_exists(section, CACHE_CFG_ID)}')
        else:
            logging_debugs.append(f'Cache [{CACHE_CFG_ID}] -> init app cfg')

        cfg_app = config_app(logging_enable=False)
        logging_debugs.append(f'Config [app]: {jpp(cfg_app)}')
        for app_key in cfg_app:
            if app_key.startswith('app_') and app_key.upper() in globals():
                globals()[app_key.upper()] = cfg_app[app_key]
                logging_debugs.append(f'Init global var [{app_key.upper()}]: {cfg_app[app_key]}')

        # init logging (basicConfig only)
        cfg_logging = config_app('logging', logging_enable=False)
        logging_basic_сonfigs = dict((key.replace('base_config_', '').lower(), cfg_logging[key]) for key in cfg_logging.keys() if key.startswith('base_config_'))
        logging.basicConfig(**logging_basic_сonfigs, force=True)
        logging_debugs.append(f'Init logging.basicConfig: {logging_basic_сonfigs}')
    finally:
        logging.debug('\n'.join(logging_debugs))  # note: if logging is not initialized then output -> uwsgi log

def parse_request(env) -> tuple[str, dict]:
    """ Parse request: resolve method, load method config, merge request method params with defaults.
        Return: method name string, method params dict """
    request_method = env['REQUEST_METHOD'].upper()
    url_parts = urlparse(unquote(env['REQUEST_URI']))
    logging.debug('Start %s request parsing: %s', request_method, url_parts)
    query_str, method_params = "", {}
    if request_method in ['HEAD', 'GET']:
        query_str = url_parts.query
    elif request_method == 'POST':
        try:
            content_length = int(env.get('CONTENT_LENGTH', 0))
        except ValueError:
            content_length = 0
        if content_length:
            query_str = env['wsgi.input'].read(content_length).decode()
    else:
        raise HttpException(HTTPStatus.BAD_REQUEST, f'{request_method} is invalid for resource {url_parts.path}')
    if query_str:
        method = url_parts.path.rpartition("/")[-1]
        method_params = dict(parse_qsl(query_str, keep_blank_values=True))
    else:
        method = APP_DEFAULT_METHOD
        method_params['ip'] = url_parts.path.rpartition("/")[-1]
    method_config = config_method(method)
    default_method_params = dict((key.replace('request_param_', '').lower(), method_config[key]) for key in method_config.keys() if key.startswith('request_param_'))
    method_params = default_method_params | method_params  # merge method params with defaults from config app section [app.{method}] request_param_* values
    logging.debug('Request parsed: method=%s\nmethod_params=[%s]\nmethod_config=[%s]', method, jpp(method_params), jpp(method_config))
    return method, method_params

def uwsgi_method(method: str, cache_key_name: str):
    """
    Func/decorator
    1) add uwsgi caching according to [app.api.{method}] settings in app cfg ini
        if {cache_id} is present in [app.api.{method}] section settings, then caching is used - according its settings in [uwsgi] (with pickle serialization)
        {cache_key_name} value is used as key for cache. {cache_key_name} param may not be defined in func itself so key value can be assigned externally
    2) add {cfg} attribute (= config_method(method)) to func (method can call each other, so we need keep config trace smh)
    """
    def decorator(func):
        # # func.cfg = config_method(method) - doesn't work since config_method() should be resolved/called here - before putting to cache method cfg settings
        # func.cfg = lambda : config_method(method) - it works here but as crutch wise ) 
        @wraps(func)
        def wrapper(*args, **kwargs):
            wrapper.cfg = config_method(method) # __wrapped__
            cache_id = wrapper.cfg.get(METHOD_CACHE_ID, None)
            cache_on = bool(cache_id)  # not not cache_id
            cache_expires = int(wrapper.cfg.get(METHOD_CACHE_EXPIRES, "0"))
            args_spec = inspect.getfullargspec(func).args
            if cache_key_name in kwargs:
                key_val = kwargs[cache_key_name] if cache_key_name in args_spec else kwargs.pop(cache_key_name)
            else:
                key_val = args[args_spec.index(cache_key_name)]  # if not exists KeyError will be raised
            if isinstance(key_val, dict):
                key_val = hash(tuple(sorted(key_val.items(), key=lambda item: item[0])))
            key_val = f'{method}:{str(key_val)}'
            if cache_on and uwsgi.cache_exists(key_val, cache_id):
                value = uwsgi.cache_get(key_val, cache_id)
                value = pickle.loads(value)
                logging.debug('cache [%s] -> %s : %s', cache_id, key_val, value)
                return value
            result = func(*args, **kwargs)
            if cache_on:
                value = pickle.dumps(result)
                uwsgi.cache_set(key_val, value, cache_expires, cache_id)
                logging.debug('cache [%s] <- %s expires %d : %s', cache_id, key_val, cache_expires, value)
            return result
        return wrapper
    return decorator

@uwsgi_method('ipinfo', 'ip_address')
def method_ipinfo(ip_address:str) -> dict:
    """ Return details for ip address provided by ipinfo.io api """
    try:
        ipinfo_key = method_ipinfo.cfg['key']  # pylint: disable=no-member
        time_out = float(method_ipinfo.cfg.get('request_time_out',  DEFAULT_REQUEST_TIME_OUT))  # pylint: disable=no-member
        handler = ipinfo.getHandler(ipinfo_key, request_options={'timeout': time_out})  # internal cache ipinfo : cache_options={'ttl':30, 'maxsize': 128} - is not used here
        return handler.getDetails(ip_address).details
    except KeyError as err:
        raise HttpException(details='Invalid app config settings: ipconfig key is missing.') from err
    except requests.exceptions.HTTPError as err:
        raise HttpException(HTTPStatus(err.response.status_code), str(err)) from err

@uwsgi_method('weather', 'params')
def method_weather(params: dict) -> Response:
    """ Return cached response from openweathermap api:weather """
    return process_openweathermap(params, method_weather.cfg)  # pylint: disable=no-member

@uwsgi_method('onecall', 'params')
def method_onecall(params: dict) -> Response:
    """ Return cached response from openweathermap api:onecall """
    return process_openweathermap(params, method_onecall.cfg)  # pylint: disable=no-member

def process_openweathermap(params, cfg) -> Response:
    """
    Process one of api.openweathermap.org method call as specified in {cfg} dict + passing {params} in request.
    Return actual status line, specified headers and content 'as is' from provider
    """
    headers = json.loads(cfg.get('request_headers', '{}'))  # '{"Connection": "close"}'
    # openweather supports head, get and post http methods, let's use get one
    with requests.get(
            url = cfg['request_url_path'],
            params = params,
            headers = headers,
            timeout = float(cfg.get('request_time_out', 0)) # https://docs.python-requests.org/en/master/user/quickstart/#timeouts
        ) as response:
        logging.debug('request url %s headers: %s', response.request.url, response.request.headers)
        response_status = status_line(HTTPStatus(response.status_code))
        response_headers_list_relay = [header.strip().title() for header in cfg.get('response_headers_list_relay', '').split(',')]
        response_headers = dict((k, v) for k, v in response.headers.items() if k in response_headers_list_relay)
        response_content = response.content
        response_headers['Server'] = response_headers.get('Server', APP_SERVER_NAME)
        response_headers['Date'] = response_headers.get('Date', gmtime_string())
        response_headers['Content-Type'] = response_headers.get('Content-Type', response.headers.get('Content-Type', f'application/json; charset={APP_ENC_HTML_DEFAULT}'))
        response_headers['Content-Length'] = response_headers.get('Content-Length', str(len(response_content)))
        response_headers['Connection'] = response_headers.get('Connection', 'close')
        return Response(response_status, response_headers, response_content)

def do_ipinfo(params: dict) -> Response:
    """ api:ipinfo method implementation """
    ip_details = method_ipinfo(ip_address = params['ip'])
    content = wsgi_to_bytes(json.dumps(ip_details))
    headers = {
        'Server': APP_SERVER_NAME,
        'Date': gmtime_string(),
        'Content-Type': f'application/json; charset={APP_ENC_HTML_DEFAULT}', #ENC
        'Content-Length': str(len(content)),
        'Connection': 'close',
    }
    return Response(status_line(HTTPStatus.OK), headers, content)

def do_weather(params: dict) -> Response:
    """ api:weather method implementation """
    translate_openweather_params(params)
    return method_weather(params)

def do_onecall(params: dict) -> Response:
    """ api:onecall method implementation """
    translate_openweather_params(params)
    return method_onecall(params)

def geoloc(ip_address: str) -> dict:
    """ Return {'lat':, 'lon':} values for {ip_address} """
    ip_details = method_ipinfo(ip_address)
    return {'lat': ip_details['latitude'], 'lon': ip_details['longitude']}

def translate_openweather_params(params):
    """ Translate inplace {params} for openweather provider """
    ip_address = params.pop('ip', None)
    if ip_address:
        params.update(geoloc(ip_address))
    if not params.keys() >= {'lat', 'lon'}:
        raise HttpException(HTTPStatus.BAD_REQUEST, 'Geolocation is missing in request.')
    if 'lang' in params:
        params['lang'] = params['lang'][:2]


def error_response(err) -> Response:
    """ Convert any exception to Response type """
    if not isinstance(err, HttpException):
        err = HttpException(exception=err)
    return Response(err.status_line, err.headers, err.content)

def send_response(env, start_response, response: Response) -> list:
    """ Send response status, headers and return content according to uwsgi specification """
    start_response(response.status_line, list(response.headers.items()))
    logging.info('Completed with status %s', response.status_line)
    if env['REQUEST_METHOD'] == 'HEAD':
        return []
    return [response.content]

def application(env, start_response):
    """ uwsgi application entry point (as specified in [uwsgi]: module = ip2w:{application}) """
    try:
        init(env)
        logging.info('Start processing request from %s:%s with uri: %s', env['REMOTE_ADDR'], env['REMOTE_PORT'], env['REQUEST_URI'])
        method, method_params = parse_request(env)
        if _do_func := globals().get(f'do_{method}', None):
            return send_response(env, start_response, _do_func(method_params))
        raise HttpException(HTTPStatus.NOT_IMPLEMENTED, f'Method [{method}] is not implemented.')
    except BaseException as err:   # pylint: disable=broad-except
        logging.exception(err, exc_info=True, stack_info=True)
        return send_response(env, start_response, error_response(err))
