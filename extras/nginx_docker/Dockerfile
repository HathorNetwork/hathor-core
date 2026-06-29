FROM nginx:stable-alpine
RUN rm /etc/nginx/conf.d/default.conf
COPY cors_params /etc/nginx/cors_params
COPY proxy_params /etc/nginx/proxy_params
COPY set_real_ip_from_cloudfront /etc/nginx/set_real_ip_from_cloudfront
