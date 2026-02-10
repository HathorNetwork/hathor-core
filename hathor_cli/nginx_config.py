# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
from enum import Enum
from typing import Any, NamedTuple, Optional, TextIO

BASE_PATH = os.path.join(os.path.dirname(__file__), 'nginx_files')


def get_openapi(src_file: Optional[TextIO] = None) -> dict[str, Any]:
    """ Open and parse the json file or generate OpenAPI dict on-the-fly
    """
    if src_file is None:
        from hathor_cli.openapi_json import get_openapi_dict
        return get_openapi_dict()
    else:
        return json.load(src_file)


def warn(msg: str) -> None:
    """ Print a warning to stderr
    """
    import sys
    print(msg, file=sys.stderr)


class Visibility(Enum):
    PRIVATE = 'private'
    PUBLIC = 'public'


class RateLimitZone(NamedTuple):
    name: str
    key: str
    size: str
    rate: str

    def to_nginx_config(self) -> str:
        """ Convert to nginx configuration line
        """
        return f'limit_req_zone {self.key} zone={self.name}:{self.size} rate={self.rate};\n'


class RateLimit(NamedTuple):
    zone: str
    burst: Optional[int] = None
    delay: Optional[int] = None

    def to_nginx_config(self) -> str:
        """ Convert to nginx configuration line
        """
        conf = f'limit_req zone={self.zone}'
        if self.burst is not None:
            conf += f' burst={self.burst}'
        if self.delay is not None:
            if self.delay == 0:
                conf += ' nodelay'
            else:
                conf += f' delay={self.delay}'
        conf += ';\n'
        return conf


def _scale_rate_limit(raw_rate: str, rate_k: float) -> str:
    """ Multiplies a string rate limit by a contant amount returning a valid rate limit

    Examples:
    >>> _scale_rate_limit('10r/s', 0.5)
    '5r/s'
    >>> _scale_rate_limit('1r/s', 0.5)
    '30r/m'
    >>> _scale_rate_limit('1r/s', 2.5)
    '2r/s'
    """
    if not raw_rate.endswith('r/s') or raw_rate.endswith('r/m'):
        raise ValueError(f'"{raw_rate}" must end in either "r/s" or "r/m"')
    raw_rate_amount = int(raw_rate[:-3])
    rate_units = raw_rate[-3:]
    scaled_rate_amount = raw_rate_amount * rate_k
    if scaled_rate_amount < 1:
        if rate_units == 'r/m':
            raise ValueError(f'final rate {scaled_rate_amount}r/m is too small')
        rate_units = 'r/m'
        scaled_rate_amount *= 60
    if scaled_rate_amount < 1:
        raise ValueError(f'final rate {scaled_rate_amount}r/m is too small')
    return f'{int(scaled_rate_amount)}{rate_units}'


def _get_visibility(source: dict[str, Any], fallback: Visibility, override: str) -> tuple[Visibility, bool, bool]:
    if 'x-visibility-override' in source and override in source['x-visibility-override']:
        visibility = source['x-visibility-override'][override]
        return Visibility(visibility), False, True
    if 'x-visibility' in source:
        return Visibility(source['x-visibility']), False, False
    else:
        return fallback, True, False


def generate_nginx_config(openapi: dict[str, Any], *, out_file: TextIO, rate_k: float = 1.0,
                          fallback_visibility: Visibility = Visibility.PRIVATE,
                          disable_rate_limits: bool = False,
                          override: str = "") -> None:
    """ Entry point of the functionality provided by the cli
    """
    from datetime import datetime

    from hathor.conf.get_settings import get_global_settings

    settings = get_global_settings()
    api_prefix = settings.API_VERSION_PREFIX

    locations: dict[str, dict[str, Any]] = {}
    limit_rate_zones: list[RateLimitZone] = []
    for path, params in openapi['paths'].items():
        visibility, did_fallback, did_override = _get_visibility(params, fallback_visibility, override)
        if did_fallback:
            warn(f'Visibility not set for path `{path}`, falling back to {fallback_visibility}')
        if did_override:
            warn(f'Visibility overridden for path `{path}` to {visibility}')
        if visibility == Visibility.PRIVATE:
            continue

        location_params: dict[str, Any] = {
            'rate_limits': [],
            'path_vars_re': params.get('x-path-params-regex', {}),
            'proxy_buffers': params.get('x-proxy-buffers'),
        }

        allowed_methods = {'OPTIONS'}
        for method in 'get post put patch delete head options trace'.split():
            if method not in params:
                continue
            method_params = params[method]
            method_visibility, _, _ = _get_visibility(method_params, Visibility.PUBLIC, override)
            if method_visibility == Visibility.PRIVATE:
                continue
            allowed_methods.add(method.upper())
        location_params['allowed_methods'] = sorted(allowed_methods)

        if not allowed_methods:
            warn(f'Path `{path}` has no public methods but is public')
            continue

        rate_limits = params.get('x-rate-limit')
        if not rate_limits:
            warn(f'Path `{path}` is public but has no rate limits, ignoring')
            continue

        path_key = path.lower().replace('/', '__').replace('.', '__').replace('{', '').replace('}', '')

        if not disable_rate_limits:
            global_rate_limits = rate_limits.get('global', [])
            for i, rate_limit in enumerate(global_rate_limits):
                # zone, for top level `limit_req_zone`
                name = f'global{path_key}__{i}'  # must match [a-z][a-z0-9_]*
                size = '32k'  # min is 32k which is enough
                rate = _scale_rate_limit(rate_limit['rate'], rate_k)
                zone = RateLimitZone(name, '$global_key', size, rate)
                limit_rate_zones.append(zone)
                # limit, for location level `limit_req`
                burst = rate_limit.get('burst')
                delay = rate_limit.get('delay')
                location_params['rate_limits'].append(RateLimit(zone.name, burst, delay))

            per_ip_rate_limits = rate_limits.get('per-ip', [])
            for i, rate_limit in enumerate(per_ip_rate_limits):
                name = f'per_ip{path_key}__{i}'  # must match [a-z][a-z0-9_]*
                # zone, for top level `limit_req_zone`
                size = '10m'
                rate = _scale_rate_limit(rate_limit['rate'], rate_k)
                zone = RateLimitZone(name, '$per_ip_key', size, rate)
                limit_rate_zones.append(zone)
                # limit, for location level `limit_req`
                burst = rate_limit.get('burst')
                delay = rate_limit.get('delay')
                location_params['rate_limits'].append(RateLimit(zone.name, burst, delay))

        locations[path] = location_params

    # TODO: consider using a templating engine

    # TODO: consider placing this parameters somewhere else
    # TODO: justify these limits:
    # XXX: global limit is based around performance testing on a c5.large+docker
    # XXX: per ip limit is based on the arbitrary choice of 5 clients per IP (to account for NATing) and a bit of
    #      margin of 2 conns per client, in practice we will probably end up changing this up or down.
    #      another possible reasoning considered was estimating the client capacity per node based on the parameters
    #      already set on http endpoints, but the fact that request limiting can have bursts, and also that the rate of
    #      global vs per ip vary a lot, this was nor persuited.
    if disable_rate_limits:
        websocket_max_conn_global = 10000
        websocket_max_conn_per_ip = 10000
        mining_websocket_max_conn_global = 1000
        mining_websocket_max_conn_per_ip = 1000
        event_websocket_max_conn_global = 1000
        event_websocket_max_conn_per_ip = 1000
    else:
        websocket_max_conn_global = 4000
        websocket_max_conn_per_ip = 10
        mining_websocket_max_conn_global = 100
        mining_websocket_max_conn_per_ip = 4
        event_websocket_max_conn_global = 100
        event_websocket_max_conn_per_ip = 4

    header = f'''# THIS FILE WAS AUTOGENERATED BY THE `hathor-cli nginx-config` TOOL AT {datetime.now()}

server_tokens off;

geo $should_limit {{
    default 1;
    # Whitelist ELB IPs:
    10.0.0.0/8 0;
    172.16.0.0/12 0;
    192.168.0.0/16 0;
}}

map $should_limit $per_ip_key {{
    0 "";
    1 $binary_remote_addr;
}}

map $should_limit $global_key {{
    0 "";
    1 "global";
}}

limit_conn_zone $global_key zone=global__ws:32k;
limit_conn_zone $per_ip_key zone=per_ip__ws:10m;
limit_conn_zone $global_key zone=global__mining_ws:32k;
limit_conn_zone $per_ip_key zone=per_ip__mining_ws:10m;
limit_conn_zone $global_key zone=global__event_ws:32k;
limit_conn_zone $per_ip_key zone=per_ip__event_ws:10m;
'''

    server_open = f'''
upstream backend {{
    server 127.0.0.1:8080;
}}

server {{
    listen 80;
    listen [::]:80;
    server_name localhost;

    # Look for client IP in the X-Forwarded-For header
    real_ip_header X-Forwarded-For;
    # Ignore trusted IPs
    real_ip_recursive on;
    # Set ELB IP as trusted
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    set_real_ip_from 192.168.0.0/16;
    # Trust CloudFront
    # See: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html
    include set_real_ip_from_cloudfront;


    client_max_body_size 10M;
    limit_req_status 429;
    limit_conn_status 429;
    error_page 429 @429;
    location @429 {{
        include cors_params;
        try_files /path/doesnt/matter =429;
    }}
    location ~ ^/{api_prefix}/ws/?$ {{
        limit_conn global__ws {websocket_max_conn_global};
        limit_conn per_ip__ws {websocket_max_conn_per_ip};
        include cors_params;
        include proxy_params;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_pass http://backend;
    }}
    location ~ ^/{api_prefix}/mining_ws/?$ {{
        limit_conn global__mining_ws {mining_websocket_max_conn_global};
        limit_conn per_ip__mining_ws {mining_websocket_max_conn_per_ip};
        include cors_params;
        include proxy_params;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_pass http://backend;
    }}
    location ~ ^/{api_prefix}/event_ws/?$ {{
        limit_conn global__event_ws {event_websocket_max_conn_global};
        limit_conn per_ip__event_ws {event_websocket_max_conn_per_ip};
        include cors_params;
        include proxy_params;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_pass http://backend;
    }}'''
    # TODO: maybe return 403 instead?
    server_close = f'''
    location /{api_prefix} {{
        return 403;
    }}
    location / {{
        return 404;
    }}
}}
'''

    out_file.write(header)

    # http level settings
    for zone in sorted(limit_rate_zones):
        out_file.write(zone.to_nginx_config())

    out_file.write(server_open)
    # server level settings
    for location_path, location_params in locations.items():
        location_path = location_path.replace('.', r'\.').strip('/').format(**location_params['path_vars_re'])
        location_open = f'''
    location ~ ^/{api_prefix}/{location_path}/?$ {{
        include cors_params;
        include proxy_params;
'''
        location_close = '''\
        proxy_pass http://backend;
    }'''
        out_file.write(location_open)
        methods = ' '.join(location_params['allowed_methods'])
        out_file.write(' ' * 8 + f'limit_except {methods} {{ deny all; }}\n')
        for rate_limit in location_params.get('rate_limits', []):
            out_file.write(' ' * 8 + rate_limit.to_nginx_config())
        proxy_buffers = location_params.get('proxy_buffers')
        if proxy_buffers:
            out_file.write(' ' * 8 + f'proxy_buffers {proxy_buffers};\n')
        out_file.write(location_close)
    out_file.write(server_close)


def main():
    import argparse
    import sys

    from hathor_cli.util import create_parser

    parser = create_parser()
    parser.add_argument('-k', '--rate-multiplier', type=float, default=1.0,
                        help='How much to multiply all rates by (float)')
    parser.add_argument('-i', '--input-openapi-json', type=argparse.FileType('r', encoding='UTF-8'), default=None,
                        help='Input file with OpenAPI json, if not specified the spec is generated on-the-fly')
    parser.add_argument('--fallback-visibility', type=Visibility, default=Visibility.PRIVATE,
                        help='Set the visibility for paths without `x-visibility`, defaults to private')
    parser.add_argument('--disable-rate-limits', type=bool, default=False,
                        help='Disable including rate-limits in the config, defaults to False')
    parser.add_argument('--override', type=str, default='',
                        help='Override visibility for paths with `x-visibility-override` for the given value')
    parser.add_argument('out', type=argparse.FileType('w', encoding='UTF-8'), default=sys.stdout, nargs='?',
                        help='Output file where nginx config will be written')
    args = parser.parse_args()

    openapi = get_openapi(args.input_openapi_json)
    generate_nginx_config(openapi, out_file=args.out, rate_k=args.rate_multiplier,
                          fallback_visibility=args.fallback_visibility,
                          disable_rate_limits=args.disable_rate_limits,
                          override=args.override)
