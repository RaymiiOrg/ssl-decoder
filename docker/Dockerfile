FROM php:7.0-apache
RUN apt-get update && apt-get install -y \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libmcrypt-dev \
        libpng12-dev \
        zlib1g-dev \
        libicu-dev \
        g++ \
        python2.7 \
        python-all-dev \
        python-netaddr \   
        perl \
        dnsutils \
        wget \
    && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin \
    && docker-php-ext-configure intl \
    && docker-php-ext-install -j$(nproc) iconv \
    && docker-php-ext-install -j$(nproc) mcrypt \
    && docker-php-ext-install -j$(nproc) mbstring \
    && docker-php-ext-install -j$(nproc) bcmath \
    && docker-php-ext-install -j$(nproc) intl \
    && docker-php-ext-configure gd --with-freetype-dir=/usr/include/ --with-jpeg-dir=/usr/include/ \
    && docker-php-ext-install -j$(nproc) gd \
    && mkdir -p /usr/local/src \
    && cd /usr/local/src \
    && wget https://openssl.org/source/openssl-1.1.0-pre4.tar.gz \
    && tar -xf openssl-1.1.0-pre4.tar.gz \
    && cd openssl-1.1.0-pre4 \
    && ./config --prefix=/usr/local no-afalgeng \
    && make \
    && make install 

