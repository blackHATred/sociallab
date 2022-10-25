# Последний образ ubuntu из Docker Hub
FROM ubuntu:latest
# Применяем все обновления
RUN apt-get -y update && apt-get install -y
# Может пригодится для redis
RUN apt -y install lsb-release
# Устанавливаем g++, cmake и redis
RUN apt-get -y install g++ cmake gdb redis lsof
# Копируем все файлы из локальной директории
COPY . .
WORKDIR .
# Открываем 9080 и 6379 порты
EXPOSE 6379
EXPOSE 9080
RUN service redis-server start
# RUN lsof -i -P -n
RUN redis-cli ping
# Устанавливаем vcpkg и все зависимости
RUN bash install.sh
RUN mkdir build
# Компилируем
RUN cmake -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake -B/build -S/
RUN cmake --build /build
# Запускаем скомпилированное приложение
CMD ./build/social3