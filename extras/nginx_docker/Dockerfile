# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

# Pinned to a release line: `stable-alpine` moved to nginx 1.30 in 2026-04, which silently turned on upstream
# keepalive (see `UPSTREAM_KEEPALIVE_TIMEOUT_SECONDS` in `hathor_cli/nginx_config.py`). Review nginx defaults before
# moving to a new line.
FROM nginx:1.30-alpine
RUN rm /etc/nginx/conf.d/default.conf
COPY cors_params /etc/nginx/cors_params
COPY proxy_params /etc/nginx/proxy_params
COPY set_real_ip_from_cloudfront /etc/nginx/set_real_ip_from_cloudfront
COPY nginx.conf /etc/nginx/conf.d/hathor.conf
