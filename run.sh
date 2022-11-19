#!/bin/bash
# Обновляем пакеты
apt -y update
# Устанавливаем nginx, закидываем базовую конфигурацию сервера и применяем настройки
apt -y install nginx
apt -y install apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
apt-cache policy docker-ce
apt -y install docker-ce
usermod -aG docker "$USER"

cp nginx_config.txt /etc/nginx/sites-available/social_server
ln -s /etc/nginx/sites-available/social_server /etc/nginx/sites-enabled/
sudo systemctl restart nginx
# Теперь создаём образ докера и привязываем к 9080 порту
docker build . -t social_server
# docker run -p 9080:9080 -p 6379:6379 -it social_server
docker run --network host social_server
echo "Контейнер запущен"