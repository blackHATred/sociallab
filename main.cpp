#include <iostream>
#include <string>
#include "crow.h"
#include "misc.cpp"
#include <sw/redis++/redis++.h>
#include <nlohmann/json.hpp>
#include <unordered_set>
#include <stdexcept>
#include <mutex>
#include <utility>

using namespace std;
using json = nlohmann::json;

long long int last_user = -1;
long long int last_msg = -1;

class User {
public:
    string server = "localhost";
    long unsigned int id{};
    vector<long unsigned int> friends;
    vector<long unsigned int> blacklist;
    string password;
    string description;
    string name;

    void save_user(sw::redis::Redis db) {
        json data;
        data["id"] = id;
        data["friends"] = friends;
        data["blacklist"] = blacklist;
        data["password"] = password;
        data["description"] = description;
        data["name"] = name;
        db.set(to_string(id)+":"+server, data.dump());
    }

    static User get_user(sw::redis::Redis db, long unsigned int user_id, const string& user_server = "localhost") {
        auto json_info = db.get(to_string(user_id)+":"+user_server);
        User user;
        if (json_info) {
            json data = json::parse(*json_info);
            data["id"].get_to(user.id);
            data["friends"].get_to(user.friends);
            data["blacklist"].get_to(user.blacklist);
            data["password"].get_to(user.password);
            data["description"].get_to(user.description);
            data["name"].get_to(user.name);
        } else {
            throw runtime_error("Пользователя с таким айди не существует!");
        }
        return user;
    }

    static long unsigned int register_user(sw::redis::Redis db, string name, string password) {
        User user;
        user.id = last_user + 1;
        last_user++;
        db.set("last_user", to_string(last_user));
        user.name = std::move(name);
        user.description = "Новый пользователь";
        user.friends = vector<long unsigned int>();
        user.blacklist = vector<long unsigned int>();
        user.password = std::move(password);
        user.save_user(db);
        return user.id;
    }

    static string get_users_method(const sw::redis::Redis &db) {
        /** Все пользователи в JSON для API */
        json data = json::array();
        User user;
        for (long unsigned int i = 0; i < last_user+1; i++) {
            user = get_user(db, i);
            data.insert(data.end(), {{user.id, user.name}});
        }
        return data.dump();
    }
};

class Message {
public:
    long long unsigned int id;
    string msg;
    bool read; // сообщение прочитано
    long unsigned int senderId;
    string senderName;
    string senderServer = "localhost";
    long unsigned int receiverId;
    // string receiverName;
    string receiverServer = "localhost";
    long int time;

    void save_msg(sw::redis::Redis db) {
        json data;
        data["id"] = id;
        data["msg"] = msg;
        data["read"] = read;
        data["senderId"] = senderId;
        data["senderName"] = senderName;
        data["senderServer"] = senderServer;
        data["receiverId"] = receiverId;
        // data["receiverName"] = receiverName;
        data["receiverServer"] = receiverServer;
        data["time"] = time;
        db.set(to_string(id), data.dump());
    }

    void send_msg(sw::redis::Redis db, string text_msg,  long unsigned int sender_id, string sender_name, long unsigned int receiver_id, string receiver_server = "localhost"){
        /** Отправка сообщения
         * senderServer по умолчанию всегда localhost
         * TODO Доделать
         * */
         Message Msg;
         Msg.msg = std::move(text_msg);
         Msg.senderId = sender_id;
         Msg.senderName = std::move(sender_name);
         Msg.receiverId = receiver_id;
    }

    static Message get_msg(sw::redis::Redis db, long unsigned int msg_id) {
        auto json_info = db.get(to_string(msg_id));
        Message msg;
        if (json_info) {
            json data = json::parse(*json_info);
            data["id"].get_to(msg.id);
            data["msg"].get_to(msg.msg);
            data["senderId"].get_to(msg.senderId);
            data["senderName"].get_to(msg.senderName);
            data["senderServer"].get_to(msg.senderServer);
            data["receiverId"].get_to(msg.receiverId);
            // data["receiverName"].get_to(msg.receiverName);
            data["time"].get_to(msg.time);
            return msg;
        } else {
            throw runtime_error("Пользователя с таким айди не существует!");
        }
    }

    json last_messages(sw::redis::Redis db, long unsigned int receiver_id, long unsigned int from_id, string from_server = "localhost") {
        /** Последние 100 сообщений, которые пришли пользователю (или он сам их отправил), в формате JSON */
        json data = json::array();
        Message msg;
        for (long unsigned int i = 0; i < last_msg+1; i++) {
            msg = Message::get_msg(db, i);
            if ((msg.receiverId == receiver_id || msg.senderId == receiver_id) && to_string(msg.senderId)+":"+msg.senderServer == to_string(from_id)+":"+from_server){
                data.insert(data.end(), json::object({{"id", msg.id},
                                                      {"msg", msg.msg},
                                                      {"senderId", msg.senderId},
                                                      {"senderName", msg.senderName},
                                                      {"senderServer", msg.senderServer},
                                                      {"receiverId", msg.receiverId},
                                                      {"time", msg.time}}));
            }
        }
        return data.dump();
    }
};

class Moderation {
    long unsigned int msgId;
    long unsigned int fromId;
    long unsigned int toId;

    void create_moderation(sw::redis::Redis db) {
        json data;
        data["msgId"] = msgId;
        data["fromId"] = fromId;
        data["toId"] = toId;
        db.set(to_string(msgId), data.dump());
    }
};

int main(int argc, char *argv[]) {
#ifdef __linux__
    setlocale(LC_ALL, "Russian");
#else
    system("chcp 65001");
#endif
    crow::SimpleApp app;
    /**
     * БД 0 - для пользователей
     * БД 1 - для сообщений
     * БД 2 - для жалоб
     * БД 3 - для тестов :)
     */
    string redis_ip;
    int redis_port = 6379;
    if (argc > 1) {
        redis_ip = argv[1];
        cout << "Подключение к Redis по " << redis_ip << ":" << redis_port;
    } else {
        redis_ip = "localhost";
    }
    sw::redis::ConnectionOptions connection_options;
    connection_options.host = redis_ip;
    connection_options.port = redis_port;
    connection_options.db = 0;
    auto user_db = sw::redis::Redis(connection_options);
    connection_options.db = 1;
    auto msg_db = sw::redis::Redis(connection_options);
    connection_options.db = 2;
    auto moderation_db = sw::redis::Redis(connection_options);
    connection_options.db = 3;
    // Айди последнего пользователя, по умолчанию -1
    if (user_db.get("last_user")) {
        sscanf_s(user_db.get("last_user")->c_str(), "%lld", &last_user);
    } else {
        user_db.set("last_user", "-1");
    }
    // Айди последнего сообщения, по умолчанию -1
    if (user_db.get("last_msg")) {
        sscanf_s(user_db.get("last_msg")->c_str(), "%lld", &last_user);
    } else {
        user_db.set("last_msg", "-1");
    }

    CROW_ROUTE(app, "/")([]() {
        // Рендер базовой страницы
        auto page = crow::mustache::load_text("index.html");
        return page;
    });
    CROW_ROUTE(app, "/get_users")([&user_db]() {
        // Все пользователи сервера
        crow::json::wvalue response(crow::json::load(User::get_users_method(user_db)));
        return response;
    });
    CROW_ROUTE(app, "/msg").methods("POST"_method)([](const crow::request &req) {
        crow::json::wvalue request(crow::json::load(req.body));
        crow::json::wvalue response;
        response["status"] = "success";
        return response;
    });
    CROW_ROUTE(app, "/command").methods("POST"_method)([&user_db](const crow::request &req) {
        // Возможен сценарий, когда со стороны клиента приходит неверный JSON. Тогда в ответ просто вернётся пустой JSON :Р
        json command = json::parse(req.body);
        crow::json::wvalue response;
        if (command["command"] == "ping") {
            response["msg"] = "pong";
        } else if (command["command"] == "register") {
            try {
                long unsigned int temp_id = User::register_user(user_db, command["name"], command["password"]);
                response["msg"] = "Регистрация успешно завершена! <strong>Ваш айди для входа: " + to_string(temp_id) +
                                  "</strong>";
            }
            catch (const std::exception &e) {
                response["msg"] = "Не удалось произвести регистрацию из-за внезапной ошибки: " + string(e.what());
            }
        } else if (command["command"] == "help") {
            response["msg"] = R""""(Список доступных команд:<br>
1)  <strong>/ping</strong> - проверка связи с сервером<br>
2)  <strong>/help</strong> - помощь<br>
3)  <strong>/register name password</strong> - регистрация<br>
4)  <strong>/login id password</strong> - вход<br>
5)  <strong>/add_friend id [server_ip]</strong> - добавить друга по айди<br>
6)  <strong>/remove_friend id [server_ip]</strong> - удалить друга по айди<br>
7)  <strong>/chat id [server_ip]</strong> - открыть чат с пользователем по айди<br>
8)  <strong>/change_password current_password new_password</strong> - обновить пароль<br>
9)  <strong>/set_description description</strong> - установить новое описание своего профиля<br>
10) <strong>/user_info id [server_ip]</strong> - посмотреть информацию о профиле по айди<br>
11) <strong>/blacklist</strong> - пользователи в вашем чёрном списке<br>
12) <strong>/blacklist_add id [server_ip]</strong> - добавить пользователя в чёрный список<br>
13) <strong>/blacklist_remove id [server_ip]</strong> - удалить пользователя из чёрного списка<br>
14) <strong>/clear</strong> - очистить терминал<br>
Команды для чата (доступны только при открытом чате):<br>
1) <strong>/moderate msg_id</strong> - отправить жалобу на сообщение<br>
2) <strong>/exit</strong> - закрыть чат<br>
3) <strong>/load</strong> - показать последние 100 сообщений<br>)"""";
        } else if (command["command"] == "get_last_messages") {

        }
        return response;
    });

    // Websocket для онлайн-чаттинга
    mutex mtx;
    unordered_set<crow::websocket::connection *> users_connections;
    CROW_ROUTE(app, "/chat")
            .websocket()
            .onopen([&](crow::websocket::connection &conn) {
                CROW_LOG_INFO << "Новое подключение websocket";
                lock_guard<mutex> _(mtx);
                users_connections.insert(&conn);
            })
            .onclose([&](crow::websocket::connection &conn, const string &reason) {
                CROW_LOG_INFO << "Подключение было разорвано: " << reason;
                lock_guard<mutex> _(mtx);
                users_connections.erase(&conn);
            })
            .onmessage([&](crow::websocket::connection & /*conn*/, const string &data, bool is_binary) {
                lock_guard<mutex> _(mtx);
                for (auto u: users_connections)
                    if (is_binary)
                        u->send_binary(data);
                    else
                        u->send_text(data);
            });

    // Вариант для ssl
    // app.bindaddr(192.168.1.2).port(443).ssl_file("certfile.crt","keyfile.key").multithreaded().run();
    app.port(9080).multithreaded().run();
    return 0;
}