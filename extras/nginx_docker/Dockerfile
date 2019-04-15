FROM nginx:1.15-alpine

RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/hathor.conf

EXPOSE 80
