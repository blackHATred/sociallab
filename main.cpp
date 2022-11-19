#include <iostream>
#include <string>
#include "crow.h"
#include "crow/middlewares/cookie_parser.h"
#include "misc.cpp"
#include <jwt-cpp/jwt.h>
#include <sw/redis++/redis++.h>
#include <nlohmann/json.hpp>
#include <unordered_set>
#include <stdexcept>
#include <mutex>
#include <utility>
#include "totp.cpp"

using namespace std;
using json = nlohmann::json;
long long int last_user = -1;
long long int last_msg = -1;
long long int last_mdr = -1;
// Секретный код для генерации хэшей
string secret_code = "top_secret";

class User {
public:
    long unsigned int id{};
    vector<long unsigned int> friends;
    vector<long unsigned int> blacklist;
    string password;
    string description;
    string name;
    string surname;
    string login;
    bool tfa_on{};

    /**
     * Сохранение пользователя в БД
     * @param db - объект базы данных пользователей
     */
    void save_user(sw::redis::Redis db) {
        json data;
        data["id"] = id;
        data["friends"] = friends;
        data["blacklist"] = blacklist;
        data["password"] = password;
        data["description"] = description;
        data["name"] = name;
        data["surname"] = surname;
        data["login"] = login;
        data["tfa_on"] = tfa_on;
        db.set(to_string(id), data.dump());
        db.set(login, data.dump());
    }
    /**
     * Получить пользователя из БД
     * @param db - объект базы данных пользователей
     * @param user_id - id пользователя, которого нужно получить
     * @return найденный пользователь
     */
    static User get_user(sw::redis::Redis db, long unsigned int user_id) {
        auto json_info = db.get(to_string(user_id));
        User user;
        if (json_info) {
            json data = json::parse(*json_info);
            data["id"].get_to(user.id);
            data["friends"].get_to(user.friends);
            data["blacklist"].get_to(user.blacklist);
            data["password"].get_to(user.password);
            data["description"].get_to(user.description);
            data["name"].get_to(user.name);
            data["surname"].get_to(user.surname);
            data["login"].get_to(user.login);
            data["tfa_on"].get_to(user.tfa_on);
        } else {
            throw runtime_error("Пользователя с таким айди не существует!");
        }
        return user;
    }
    /**
     * Получить пользователя из БД
     * @param db - объект базы данных пользователей
     * @param login - login пользователя, которого нужно получить
     * @return найденный пользователь
     */
    static User get_user_by_login(sw::redis::Redis db, const string& login) {
        auto json_info = db.get(login);
        User user;
        if (json_info) {
            json data = json::parse(*json_info);
            data["id"].get_to(user.id);
            data["friends"].get_to(user.friends);
            data["blacklist"].get_to(user.blacklist);
            data["password"].get_to(user.password);
            data["description"].get_to(user.description);
            data["name"].get_to(user.name);
            data["surname"].get_to(user.surname);
            data["login"].get_to(user.login);
            data["tfa_on"].get_to(user.tfa_on);
        } else {
            throw runtime_error("Пользователя с таким логином не существует!");
        }
        return user;
    }
    /**
     * Регистрация пользователя
     * @param db - объект базы данных пользователей
     * @param login - логин пользователя
     * @param name - имя пользователя
     * @param surname - фамилия пользователя
     * @param password - пароль пользователя
     * @return id зарегистрированного пользователя
     */
    static long unsigned int register_user(sw::redis::Redis db, string login, string name, string surname, string password) {
        User user;
        user.id = last_user + 1;
        last_user++;
        db.set("last_user", to_string(last_user));
        user.login = std::move(login);
        user.name = std::move(name);
        user.surname = std::move(surname);
        user.description = "Новый пользователь";
        user.friends = vector<long unsigned int>();
        user.blacklist = vector<long unsigned int>();
        user.password = std::move(password);
        user.tfa_on = false;
        user.save_user(std::move(db));
        return user.id;
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

    json last_messages(sw::redis::Redis db, long unsigned int receiver_id, long unsigned int from_id) {
        /** Последние 100 сообщений, которые пришли пользователю (или он сам их отправил), в формате JSON */
        json data = json::array();
        Message msg;
        for (long unsigned int i = 0; i < last_msg+1; i++) {
            msg = Message::get_msg(std::move(db), i);
            if ((msg.receiverId == receiver_id || msg.senderId == receiver_id) && to_string(msg.senderId) == to_string(from_id)){
                data.insert(data.end(), json::object({{"id", msg.id},
                                                      {"msg", msg.msg},
                                                      {"senderId", msg.senderId},
                                                      {"senderName", msg.senderName},
                                                      {"receiverId", msg.receiverId},
                                                      {"time", msg.time}}));
            }
        }
        return data.dump();
    }
};

class Moderation {
    long unsigned int id;
    long unsigned int fromId;
    long unsigned int toId;

    void create_moderation(sw::redis::Redis db) {
        json data;
        data["fromId"] = fromId;
        data["toId"] = toId;
        db.set(to_string(id), data.dump());
    }
};

class Session {
public:
    // Будем считать, что сессии бесконечны
    // int expire;
    string token;
    /**
     * Получить пользователя по токену
     * */
    static User get_user(sw::redis::Redis db_user, const string& t){
        return User::get_user(std::move(db_user), stoll(jwt::decode(t).get_payload_claim("user_id").as_string()));
    }
    /**
     * Генерация токена для пользователя
     * */
    static string generate_token(const User& user){
        return jwt::create()
        .set_issuer("auth0")
        .set_type("JWS")
        .set_payload_claim("user_id", jwt::claim(to_string(user.id)))
        .sign(jwt::algorithm::hs256{secret_code});
    }

};

int main(int argc, char *argv[]) {
#ifdef __linux__
    setlocale(LC_ALL, "Russian");
#else
    system("chcp 65001");
#endif
    crow::App<crow::CookieParser> app;
    /**
     * БД 0 - для пользователей
     * БД 1 - для сообщений
     * БД 2 - для жалоб
     * БД 3 - для сессий
     */
    vector<uint8_t> secretKey = decodeBase32(secret_code);
    int64_t timestamp = std::time(nullptr);
    cout << calcTotp(std::move(secretKey), 0, 30, timestamp, 6, calcSha1Hash, 64) << endl;

    string redis_ip;
    int redis_port = 6379;
    if (argc > 1) {
        redis_ip = argv[1];
        cout << "Подключение к Redis по " << redis_ip << ":" << redis_port << endl;
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
    auto session_db = sw::redis::Redis(connection_options);
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
    // Айди последней жалобы, по умолчанию -1
    if (user_db.get("last_mdr")) {
        sscanf_s(user_db.get("last_mdr")->c_str(), "%lld", &last_user);
    } else {
        user_db.set("last_mdr", "-1");
    }


    CROW_ROUTE(app, "/")([](const crow::request &req, crow::response& res) {
        res.redirect("/login");
        res.end();
    });
    CROW_ROUTE(app, "/login")([&app, &user_db](const crow::request &req) {
        // Рендер базовой страницы
        auto res = crow::response();
        res.body = crow::mustache::load_text("login.html");
        auto& ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        if (!token.empty()){
            try{
                Session::get_user(user_db, token);
                res.redirect("/me");
                return res;
            }
            catch (...){
                // Токен оказался невалидным, обнуляем его
                ctx.set_cookie("token", "");
            }
        }
        if(method_name(req.method) == "GET"){
            return res;
        }
        else {
            json req_json = json::parse(req.body);
            crow::json::wvalue res_json;
            try{
                if(req_json.contains("login") && req_json.contains("password") && req_json.contains("tfa")){
                    throw runtime_error("Переданы не все данные");
                }
                auto user = User::get_user_by_login(user_db, req_json["login"]);
            }
            catch (...) {
                res_json["error"] = "Неверные данные";
            }
            return res;
        }
    });
    CROW_ROUTE(app, "/msg").methods("POST"_method)([](const crow::request &req) {
        crow::json::wvalue request(crow::json::load(req.body));
        crow::json::wvalue response;
        response["status"] = "success";
        return response;
    });
    /*
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
            response["msg"] = "";
        } else if (command["command"] == "get_last_messages") {

        }
        return response;
    });
    */

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