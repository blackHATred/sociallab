#include <iostream>
#include "crow.h"
#include "misc.cpp"
#include <sw/redis++/redis++.h>
#include <nlohmann/json.hpp>
#include <unordered_set>
#include <mutex>
#include <utility>

using namespace std;
using json = nlohmann::json;

long unsigned int last_user = 0;

class User{
public:
    string server = "localhost";
    long unsigned int id;
    vector<long unsigned int> friends;
    vector<long unsigned int> blacklist;
    string password;
    string description;
    string name;
    void save_user(sw::redis::Redis db){
        json data;
        data["id"] = id;
        data["friends"] = friends;
        data["blacklist"] = blacklist;
        data["password"] = password;
        data["description"] = description;
        data["name"] = name;
        db.set(to_string(id), data.dump());
    }
    static User get_user(sw::redis::Redis db, long unsigned int user_id){
        auto json_info = db.get(to_string(user_id));
        if (json_info){
            json data = json::parse(*json_info);
            User user;
            data["id"].get_to(user.id);
            data["friends"].get_to(user.friends);
            data["blacklist"].get_to(user.blacklist);
            data["password"].get_to(user.password);
            data["description"].get_to(user.description);
            data["name"].get_to(user.name);
            return user;
        }
        else {
            // Ошибка
        }
        return {};
    }
    static long unsigned int register_user(const sw::redis::Redis& db, string name, string password){
        User user;
        user.id = last_user + 1;
        last_user++;
        user.name = std::move(name);
        user.description = "Новый пользователь";
        user.friends = vector<long unsigned int>();
        user.blacklist = vector<long unsigned int>();
        user.password = std::move(password);
        user.save_user(db);
        return user.id;
    }
    static string get_users_method(const sw::redis::Redis& db){
        /** Все пользователи в JSON для API */
        json data = {};
        User user;
        for (long unsigned int i = 0; i != last_user; i++){
            user = get_user(db, i);
            data.insert(data.end(), {user.id, user.name, user.description});
        }
        return data.dump();
    }
};
class Message{
public:
    long long unsigned int id;
    string msg;
    bool read; // сообщение прочитано
    long unsigned int senderId;
    string senderName;
    long unsigned int receiverId;
    string receiverName;
    long int time;
    void save_msg(sw::redis::Redis db){
        json data;
        data["id"] = id;
        data["msg"] = msg;
        data["senderId"] = senderId;
        data["senderName"] = senderName;
        data["receiverId"] = receiverId;
        data["receiverName"] = receiverName;
        data["time"] = time;
        db.set(to_string(id), data.dump());
    }
    void get_msg(sw::redis::Redis db, long unsigned int msg_id){
        auto json_info = db.get(to_string(msg_id));
        if (json_info){
            json data = json::parse(*json_info);
            data["id"].get_to(id);
            data["msg"].get_to(msg);
            data["senderId"].get_to(senderId);
            data["senderName"].get_to(senderName);
            data["receiverId"].get_to(receiverId);
            data["receiverName"].get_to(receiverName);
            data["time"].get_to(time);
        }
        else {
            // Ошибка
        }
    }
};
class Moderation{
    long unsigned int msgId;
    long unsigned int fromId;
    long unsigned int toId;
    void save_msg(sw::redis::Redis db){
        json data;
        data["msgId"] = msgId;
        data["fromId"] = fromId;
        data["toId"] = toId;
        db.set(to_string(msgId), data.dump());
    }
    void get_msg(sw::redis::Redis db, long unsigned int msg_id){
        auto json_info = db.get(to_string(msg_id));
        if (json_info){
            json data = json::parse(*json_info);
            data["msgId"].get_to(msgId);
            data["fromId"].get_to(fromId);
            data["toId"].get_to(toId);
        }
        else {
            // Ошибка
        }
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
    if (argc > 1){
        redis_ip = argv[1];
        cout << "Подключение к Redis по " << redis_ip << ":" << redis_port;
    }
    else {
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
    auto test_db = sw::redis::Redis(connection_options);
    test_db.set("", "");

    // Айди последнего пользователя, по умолчанию -1
    user_db.set("last_user", "-1");

    CROW_ROUTE(app, "/")([]() {
        // рендер страницы
        auto page = crow::mustache::load_text("index.html");
        return page;
    });
    CROW_ROUTE(app, "/get_users")([&user_db]() {
        crow::json::wvalue response(crow::json::load(User::get_users_method(user_db)));
        return response;
    });
    CROW_ROUTE(app, "/msg").methods("POST"_method)([](const crow::request& req){
        crow::json::wvalue request(crow::json::load(req.body));
        crow::json::wvalue response;
        response["status"] = "success";
        return response;
    });
    CROW_ROUTE(app, "/command").methods("POST"_method)([&user_db](const crow::request& req){
        // Возможен сценарий, когда со стороны клиента приходит неверный JSON. Тогда в ответ просто вернётся пустой JSON :Р
        json command = json::parse(req.body);
        crow::json::wvalue response;
        if(command["command"] == "ping"){
            response["msg"] = "pong";
        }
        else if(command["command"] == "register"){
            try {
                long unsigned int temp_id = User::register_user(user_db, command["name"], command["password"]);
                response["msg"] = "Регистрация успешно завершена! <strong>Ваш айди для входа: "+to_string(temp_id)+"</strong>";
            }
            catch(const std::exception &e) {
                response["msg"] = "Не удалось произвести регистрацию из-за внезапной ошибки: " + string(e.what());
            }
        }
        else if(command["command"] == "help"){
            response["msg"] = "Список доступных команд: \n"
                              "1)  /ping - проверка связи с сервером\n"
                              "2)  /help - помощь\n"
                              "3)  /register name password - регистрация\n"
                              "4)  /login id password - вход\n"
                              "5)  /add_friend id [server_ip] - добавить друга по айди\n"
                              "6)  /remove_friend id [server_ip] - удалить друга по айди\n"
                              "7)  /chat id [server_ip] - открыть чат с пользователем по айди\n"
                              "8)  /change_password current_password new_password - обновить пароль\n"
                              "9)  /set_description description - установить новое описание своего профиля\n"
                              "10)  /user_info id [server_ip] - посмотреть информацию о профиле по айди\n"
                              "11) /blacklist - пользователи в вашем чёрном списке\n"
                              "12) /blacklist_add id [server_ip] - добавить пользователя в чёрный список\n"
                              "13) /blacklist_remove id [server_ip] - удалить пользователя из чёрного списка\n"
                              "Команды для чата (доступны только при открытом чате):\n"
                              "14) /moderate msg_id - отправить жалобу на сообщение\n"
                              "15) /exit - закрыть чат\n"
                              "16) /load - показать последние 100 сообщений\n";
        }
        else if(command["command"] == "get_last_messages"){

        }
        return response;
    });

    // Websocket для онлайн-чаттинга
    mutex mtx;
    unordered_set<crow::websocket::connection*> users_connections;
    CROW_ROUTE(app, "/chat")
            .websocket()
            .onopen([&](crow::websocket::connection& conn){
                CROW_LOG_INFO << "Новое подключение websocket";
                lock_guard<mutex> _(mtx);
                users_connections.insert(&conn);
            })
            .onclose([&](crow::websocket::connection& conn, const string& reason){
                CROW_LOG_INFO << "Подключение было разорвано: " << reason;
                lock_guard<mutex> _(mtx);
                users_connections.erase(&conn);
            })
            .onmessage([&](crow::websocket::connection& /*conn*/, const string& data, bool is_binary){
                lock_guard<mutex> _(mtx);
                for(auto u:users_connections)
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