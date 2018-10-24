FROM ubuntu:18.04

ENV HTR_PATH_DATA="/var/lib/hathor" \
    HTR_PATH_HOME="/usr/share/hathor" \
	HTR_PATH_LOGS="/var/log/hathor"

WORKDIR $HTR_PATH_HOME

COPY ./_build/requirements.txt /tmp/

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-setuptools python3-pip nginx && \
    apt-get install -y --no-install-recommends python3-dev build-essential libssl-dev && \
    pip3 install --no-cache-dir wheel && \
    pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    apt-get purge -y --auto-remove build-essential python3-dev libssl-dev && \
	rm -rf /var/lib/apt/lists/*

COPY ./install.sh ./_build/hathor.tar.gz ./_build/hathor-webadmin.tar.gz /tmp/

RUN /tmp/install.sh && \
    rm -f /tmp/install.sh /tmp/hathor.tar.gz /tmp/hathor-webadmin.tar.gz && \
    rm -f /etc/nginx/sites-enabled/default

COPY ./nginx.conf /etc/nginx/sites-available/hathor-webadmin
COPY ./run.sh /run.sh


EXPOSE 80 40403

ENTRYPOINT ["/run.sh"]
CMD []
