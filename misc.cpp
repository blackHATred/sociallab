/** Дополнительные функции */
#include <cctype>
#include <iomanip>
#include <iostream>
#include <string>
#include <boost/asio.hpp>

using namespace std;


string url_encode(const string &value) {
    /**
     * Преобразование строчки в http-закодированную
     */
    ostringstream escaped;
    escaped.fill('0');
    escaped << hex;

    for (char c: value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        escaped << uppercase;
        escaped << '%' << setw(2) << int((unsigned char) c);
        escaped << nouppercase;
    }

    return escaped.str();
}

string send_msg_out(string from_name, long int from_id, string to_name, long int to_id, string msg, string server_ip,
                    int port) {
    /** Отправка сообщения на другой сервер
     * from_name - имя отправителя
     * from_if - айди отправителя
     * to_name - имя (или логин, зависит от реализации другого сервера) получателя
     * to_id - имя получателя
     * msg - сообщение
     * server_ip - айпи сервера-получателя
     * port - порт для получения */
    using namespace boost::asio;
    boost::system::error_code ec;
    io_service svc;
    ip::tcp::socket sock(svc);
    ip::tcp::endpoint endpoint(ip::address::from_string(server_ip), port);
    sock.connect(endpoint);

    // отправляем запрос
    string request(url_encode("POST /msg?from_name="+from_name+
                              "&from_id="+to_string(from_id)+"&to_name="+to_name+"&to_id="+to_string(to_id)+"&msg="+msg+" HTTP/1.1\r\n\r\n"));
    sock.send(buffer(request));

    std::string response;
    // отправляем запрос пакетами
    do {
        char buf[1024];
        size_t bytes_transferred = sock.receive(buffer(buf), {}, ec);
        if (!ec) response.append(buf, buf + bytes_transferred);
    } while (!ec);

    // print and exit
    std::cout << "Ответ получен: '" << response << "'\n";

    return "Error";
}