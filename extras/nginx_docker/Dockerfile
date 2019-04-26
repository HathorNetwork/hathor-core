FROM nginx:1.16-alpine
RUN rm /etc/nginx/conf.d/default.conf
COPY cors_params /etc/nginx/cors_params
COPY proxy_params /etc/nginx/proxy_params
COPY nginx.conf /etc/nginx/conf.d/hathor.conf
