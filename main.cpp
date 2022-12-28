#include <jwt-cpp/jwt.h>
#include <iostream>
#include <string>
#include "crow.h"
#include "crow/middlewares/cookie_parser.h"
#include "misc.cpp"
#include <sw/redis++/redis++.h>
#include <unordered_set>
#include <stdexcept>
#include "set"
#include <mutex>
#include <utility>
#include "libcppotp/otp.h"
#include "pdf.h"
#include <cstdint>
#define SECRET_CODE "top_secret"

using namespace std;

class User {
public:
    /** ID пользователя */
    u_int64_t id{};
    /** ID друзей */
    vector<u_int64_t> friends = vector<u_int64_t>();
    /** ID каждого из ЧС */
    vector<u_int64_t> blacklist = vector<u_int64_t>();
    /** ID каждого, на кого подана жалоба */
    vector<u_int64_t> moderates = vector<u_int64_t>();
    /** Пароль */
    string password;
    /** Описание профиля */
    string description;
    /** Имя */
    string name;
    /** Фамилия */
    string surname;
    /** Логин */
    string login;
    /** Количество непрочитанных сообщений  */
    uint unread_msgs{};
    /** 2FA включен */
    bool tfa_on{};
    /** Фото профиля (base64) */
    string picture;
    /** ID всех отправленных и принятых сообщений */
    vector<u_int64_t> msgs = vector<u_int64_t>();


    /**
     * Сохранение пользователя в БД
     * @param db - объект базы данных пользователей
     */
    void save_user(sw::redis::Redis &db) const {
        if (!validate_data(login, name, surname, password))
            throw runtime_error("Невалидные данные");
        crow::json::wvalue data;
        data["id"] = id;
        data["friends"] = friends;
        data["blacklist"] = blacklist;
        data["moderates"] = moderates;
        data["password"] = password;
        data["description"] = description;
        data["name"] = to_title(name);
        data["surname"] = to_title(surname);
        data["login"] = login;
        data["unread_msgs"] = unread_msgs;
        data["tfa_on"] = tfa_on;
        data["msgs"] = msgs;
        db.set(login + "_picture", picture);
        db.set(to_string(id), data.dump());
        db.set(login, to_string(id));
    }

    /**
     * Получить пользователя из БД
     * @param db - объект базы данных пользователей
     * @param user_id - id пользователя, которого нужно получить
     * @return найденный пользователь
     */
    static User get_user(sw::redis::Redis &db, long unsigned int user_id) {
        auto json_info = db.get(to_string(user_id));
        User user;
        if (json_info) {
            auto data = crow::json::load(*json_info);
            user.id = data["id"].i();
            for (const auto &i: data["friends"]) user.friends.push_back(i.i());
            for (const auto &i: data["blacklist"]) user.blacklist.push_back(i.i());
            for (const auto &i: data["moderates"]) user.moderates.push_back(i.i());
            for (const auto &i: data["msgs"]) user.msgs.push_back(i.i());
            user.password = data["password"].s();
            user.description = data["description"].s();
            user.name = data["name"].s();
            user.surname = data["surname"].s();
            user.login = data["login"].s();
            user.unread_msgs = data["unread_msgs"].i();
            user.picture = *db.get(string(data["login"].s()) + "_picture");
            user.tfa_on = data["tfa_on"].b();
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
    static User get_user_by_login(sw::redis::Redis &db, const string &login) {
        auto user_id = db.get(login);
        if (user_id) {
            return get_user(db, stoul(user_id.value()));
        } else {
            throw runtime_error("Пользователя с таким логином не существует!");
        }
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
    static User register_user(sw::redis::Redis &db, const string &login, const string &name, const string &surname,
                              string password) {
        if (!User::validate_data(login, name, surname, password)) throw runtime_error("Данные невалидны");
        User user;
        user.id = stoll(*db.get("&last_user")) + 1;
        db.set("&last_user", to_string(user.id));
        user.login = to_lower(login);
        user.name = name;
        user.surname = surname;
        user.description = "Новый пользователь";
        user.friends = vector<u_int64_t>();
        user.blacklist = vector<u_int64_t>();
        user.moderates = vector<u_int64_t>();
        user.msgs = vector<u_int64_t>();
        user.password = std::move(password);
        user.unread_msgs = 0;
        user.tfa_on = false;
        user.picture = basic_avatar;
        user.save_user(db);
        return user;
    }

    /**
     * Проверка на валидность регистрационных данных
     * @param login - логин пользователя
     * @param name - имя пользователя
     * @param surname - фамилия пользователя
     * @param password - пароль пользователя
     * @return bool (валидно или не валидно)
     */
    static bool validate_data(const string &login = "qwerty1234",
                              const string &name = "qwerty",
                              const string &surname = "qwerty",
                              const string &password = "qwerty1234_!()") {
        string login_abc = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        string name_abc = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZабвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
        // возможно наличие двойной фамилии у пользователя, следует включить "-"
        string surname_abc = name_abc + "-";
        string password_abc = name_abc + "1234567890_!()";
        for (char i: login) { if (!login_abc.contains(i)) { return false; }}
        for (char i: name) { if (!name_abc.contains(i)) { return false; }}
        for (char i: surname) { if (!surname_abc.contains(i)) { return false; }}
        for (char i: password) { if (!password_abc.contains(i)) { return false; }}
        if (64 < login.length() || login.length() < 2) { return false; }
        if (64 < name.length() || name.length() < 2) { return false; }
        if (64 < surname.length() || surname.length() < 2) { return false; }
        if (64 < password.length() || password.length() < 8) { return false; }
        return true;
    }
};

class Message {
public:
    /** ID сообщения */
    u_int64_t id{};
    /** текст сообщения */
    string msg;
    /** сообщение прочитано */
    bool read{};
    /** ID отправителя */
    u_int64_t senderId{};
    /** ID получателя */
    u_int64_t receiverId{};
    /** Время отправления */
    u_int64_t time{};
    /** Тип сообщения (0 - сообщение, 1 - перевод денег) */
    char type{};
    /** Ответ на ID сообщения (-1 - не ответ) */
    u_int64_t reply{};
    /** Отредактировано */
    bool edited{};
    /** Поставленная реакция
     * like, dislike, hm, sad, clown */
    string reaction;

    /**
     * Получить сообщение из БД
     * @param db объект БД
     * @param msg_id ID сообщения
     * @return @Message сообщение
     */
    static Message get_msg(sw::redis::Redis &db, long unsigned int msg_id) {
        auto json_info = db.get(to_string(msg_id));
        Message msg;
        if (json_info) {
            auto data = crow::json::load(*json_info);
            msg.id = data["id"].i();
            msg.msg = data["msg"].s();
            msg.read = data["read"].b();
            msg.senderId = data["senderId"].i();
            msg.receiverId = data["receiverId"].i();
            msg.time = data["time"].i();
            msg.type = (char)data["type"].i();
            msg.reply = data["reply"].i();
            msg.edited = data["edited"].b();
            msg.reaction = data["reaction"].s();
        } else {
            throw runtime_error("Сообщения с таким айди не существует!");
        }
        return msg;
    }

    /**
     * Сохранение сообщения в БД
     * @param db - объект базы данных сообщений
     */
    void save_msg(sw::redis::Redis &db) const {
        crow::json::wvalue data;
        data["id"] = id;
        data["msg"] = msg;
        data["read"] = read;
        data["senderId"] = senderId;
        data["receiverId"] = receiverId;
        data["time"] = time;
        data["type"] = type;
        data["reply"] = reply;
        data["edited"] = edited;
        data["reaction"] = reaction;
        db.set(to_string(id), data.dump());
    }

    /**
     * Создание сообщения
     * @param msg_db - объект базы данных сообщений
     * @param user_db - объект базы данных пользователей
     * @param msg - текст сообщения
     * @param senderId - ID отправителя
     * @param receiverID - ID получателя
     * @param type - тип сообщения
     * @param reply - ответ на ID сообщения
     * @return @Message созданное сообщение
     */
    static Message send_msg(sw::redis::Redis &msg_db, sw::redis::Redis &user_db, const string& msg_,
                            u_int64_t senderId_, u_int64_t receiverId_, u_int64_t type_, u_int64_t reply_) {
        Message msg;
        msg.id = stoll(*msg_db.get("&last_msg")) + 1;
        msg_db.set("&last_msg", to_string(msg.id));
        msg.msg = msg_;
        msg.read = false;
        msg.senderId = senderId_;
        msg.receiverId = receiverId_;
        msg.time = std::time(nullptr);
        msg.type = (char)type_;
        msg.reply = reply_;
        msg.edited = false;
        msg.reaction = "";
        msg.save_msg(msg_db);
        // Добавляем пользователям новые сообщения
        // TODO: сделать всё это транзакцией для обеспечения безопасности операции и избежания аномалий в БД
        auto sender = User::get_user(user_db, senderId_);
        auto receiver = User::get_user(user_db, receiverId_);
        sender.msgs.push_back(msg.id);
        receiver.msgs.push_back(msg.id);
        sender.save_user(user_db);
        receiver.save_user(user_db);
        return msg;
    }
};

class Moderation {
private:
    u_int64_t id;
    u_int64_t fromId;
    u_int64_t toId;
    u_int64_t at_time;
public:
    /**
     * Сохранение жалобы
     * @param db база данных с жалобами
     */
    void save_moderation(sw::redis::Redis& db) const {
        crow::json::wvalue data;
        data["id"] = id;
        data["fromId"] = fromId;
        data["toId"] = toId;
        data["at_time"] = at_time;
        db.set(to_string(id), data.dump());
    }
    /**
     * Создание жалобы
     * @param db база данных с жалобами
     * @param from_id id пользователя, отправившего жалобу
     * @param to_id id пользователя, получившего жалобу
     */
    static void create_moderation(sw::redis::Redis& db, u_int64_t from_id, u_int64_t to_id) {
        Moderation mdr{};
        mdr.at_time = time(nullptr);
        mdr.id = stoll(*db.get("&last_mdr")) + 1;
        db.set("&last_mdr", to_string(mdr.id));
        mdr.toId = to_id;
        mdr.fromId = from_id;
        mdr.save_moderation(db);
    }
};

class Session {
public:
    // Будем считать, что сессии бесконечны
    // int expire;
    string token;

    /**
     * получить пользователя по токену
     * @param db_user база данных с пользователями
     * @param t токен
     * @return пользователь @User
     */
    static User get_user(sw::redis::Redis &db_user, const string &t) {
        auto decoded_token = jwt::decode(t);
        auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{SECRET_CODE})
                .with_issuer("auth0");
        verifier.verify(decoded_token);
        return User::get_user(db_user, stoll(decoded_token.get_payload_claim("user_id").as_string()));
    }

    /**
     * Генерация токена
     * @param user пользователь, которому присваивается токен
     * @return токен
     */
    static string generate_token(const User &user) {
        return jwt::create()
                .set_issuer("auth0")
                .set_type("JWS")
                .set_payload_claim("user_id", jwt::claim(to_string(user.id)))
                .sign(jwt::algorithm::hs256{SECRET_CODE});
    }

};

int main(int argc, char *argv[]) {
    setlocale(LC_ALL, "Russian");
    /*
#ifdef __linux__
    setlocale(LC_ALL, "Russian");
#else
    // SetConsoleOutputCP( 65001 );
#endif
     */
    crow::App<crow::CookieParser> app;
    /**
     * БД 0 - для пользователей
     * БД 1 - для сообщений
     * БД 2 - для жалоб
     * БД 3 - для сессий
     */
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
    // ID последнего пользователя, по умолчанию -1
    if (user_db.exists("&last_user") == 0) user_db.set("&last_user", "-1");
    // ID последнего сообщения, по умолчанию -1
    if (user_db.exists("&last_msg") == 0) msg_db.set("&last_msg", "-1");
    // ID последней жалобы, по умолчанию -1
    if (user_db.exists("&last_mdr") == 0) moderation_db.set("&last_mdr", "-1");
    /** Базовая ссылка переадресует на страницу авторизации */
    CROW_ROUTE(app, "/")([](const crow::request &req, crow::response &res) {
        res.redirect("/login");
        res.end();
    });
    /** Авторизация */
    CROW_ROUTE(app, "/login").methods("GET"_method, "POST"_method)([&app, &user_db](const crow::request &req) {
        auto res = crow::response();
        res.body = crow::mustache::load_text("login.html");
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        if (!token.empty()) {
            try {
                Session::get_user(user_db, token);
                res.redirect("/me");
                return res;
            }
            catch (...) {
                // Токен оказался невалидным, обнуляем его
                ctx.set_cookie("token", "");
            }
        }
        if (method_name(req.method) == "GET") {
            return res;
        } else {
            // json req_json = json::parse(req.body);
            auto req_json = crow::json::load(req.body);
            crow::json::wvalue res_json;
            try {
                auto user = User::get_user_by_login(user_db, req_json["login"].s());
                if (user.tfa_on) {
                    if (req_json["tfa"].s() == "") {
                        // Если пользователь пытается войти, то запрашиваем код 2fa
                        res_json["error"] = "tfa_required";
                    } else if (req_json["tfa"].i() != CppTotp::totp(reinterpret_cast<const uint8_t *>((SECRET_CODE+to_string(user.id)).c_str()), time(nullptr), 0, 30)) {
                        // Если введён неверный код двухэтапной аутентификации
                        res_json["error"] = "tfa_incorrect";
                    } else {
                        // Пароль, логин и 2fa верные
                        ctx.set_cookie("token", Session::generate_token(user));
                        res.redirect("/me");
                    }
                } else if (user.password == req_json["password"].s()) {
                    // Пароль и логин верные
                    ctx.set_cookie("token", Session::generate_token(user));
                    res.redirect("/me");
                } else {
                    throw runtime_error("Неверный пароль");
                }
            }
            catch (...) {
                res_json["error"] = "incorrect_data";
            }
            res.body = res_json.dump();
            return res;
        }
    });
    /** Регистрация */
    CROW_ROUTE(app, "/register").methods("GET"_method, "POST"_method)([&app, &user_db](const crow::request &req) {
        auto res = crow::response();
        res.body = crow::mustache::load_text("register.html");
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        if (!token.empty()) {
            try {
                Session::get_user(user_db, token);
                res.redirect("/me");
                return res;
            }
            catch (...) {
                // Токен оказался невалидным, обнуляем его
                ctx.set_cookie("token", "");
            }
        }
        if (method_name(req.method) == "GET") {
            return res;
        } else {
            auto req_json = crow::json::load(req.body);
            crow::json::wvalue res_json;
            try {
                if (!(req_json.has("login") && req_json.has("password") && req_json.has("name") &&
                      req_json.has("surname"))) {
                    throw runtime_error("Переданы не все данные");
                }
                try {
                    // проверяем, занят ли логин
                    auto user = User::get_user_by_login(user_db, req_json["login"].s());
                    res_json["error"] = "login";
                }
                catch (...) {
                    // иначе регистрируем пользователя
                    auto user = User::register_user(user_db, req_json["login"].s(), req_json["name"].s(),
                                                    req_json["surname"].s(), req_json["password"].s());
                    res_json["success"] = "success";
                }
            }
            catch (const std::exception &exc) {
                cerr << exc.what() << endl;
                res_json["error"] = "incorrect_data";
            }
            res.body = res_json.dump();
            return res;
        }
    });
    /** Выход из профиля. Чистим куки и уходим на страницу авторизации */
    CROW_ROUTE(app, "/exit").methods("GET"_method)([&app](const crow::request &req) {
        auto res = crow::response();
        auto &ctx = app.get_context<crow::CookieParser>(req);
        ctx.set_cookie("token", "");
        res.redirect("/login");
        return res;
    });
    /** Рендер страницы пользователя */
    CROW_ROUTE(app, "/me").methods("GET"_method, "POST"_method)([&app, &user_db](const crow::request &req) {
        User user;
        auto res = crow::response();
        res.body = crow::mustache::load_text("my_profile.html");
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        try {
            user = Session::get_user(user_db, token);
        }
        catch (...) {
            // Токен оказался невалидным, обнуляем его
            ctx.set_cookie("token", "");
            res.redirect("/login");
            return res;
        }
        if (method_name(req.method) == "GET") {
            return res;
        }
        // Если не GET, то меняем данные
        auto req_json = crow::json::load(req.body);
        crow::json::wvalue res_json;
        try {
            if (req_json["type"].s() == "main_info_edit") {
                user.name = req_json["name"].s();
                user.surname = req_json["surname"].s();
                user.description = req_json["description"].s();
                user.save_user(user_db);
                res_json["success"] = true;
            } else if (req_json["type"].s() == "pass_update") {
                if (user.password != req_json["password_current"].s()) {
                    res_json["error"] = "password";
                } else {
                    user.password = req_json["password_new"].s();
                    user.save_user(user_db);
                    res_json["success"] = true;
                }
            } else if (req_json["type"].s() == "profile_photo_update") {
                user.picture = req_json["photo"].s();
                user.save_user(user_db);
                res_json["success"] = true;
            } else if (req_json["type"].s() == "tfa_toggle") {
                user.tfa_on = req_json["check"].b();
                user.save_user(user_db);
                res_json["toggle"] = user.tfa_on;
            }
        }
        catch (const std::exception &exc) {
            cout << exc.what() << endl;
            res_json["error"] = true;
        }
        res.body = res_json.dump();
        return res;
    });
    /** Информация о пользователе */
    CROW_ROUTE(app, "/my_info").methods("GET"_method)([&app, &user_db, &msg_db](const crow::request &req) {
        User user;
        auto res = crow::response();
        crow::json::wvalue res_json;
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        if (token.empty()) {
            res.redirect("/login");
            return res;
        } else {
            try {
                user = Session::get_user(user_db, token);
            }
            catch (...) {
                // Токен оказался невалидным, обнуляем его
                ctx.set_cookie("token", "");
                res.redirect("/login");
                return res;
            }
            res_json["tfa_secret"] = CppTotp::Bytes::toBase32(reinterpret_cast<const uint8_t *>((SECRET_CODE+to_string(user.id)).c_str()));
            res_json["tfa_on"] = user.tfa_on;
            res_json["login"] = user.login;
            res_json["id"] = user.id;
            res_json["name"] = user.name;
            res_json["surname"] = user.surname;
            res_json["description"] = user.description;
            res_json["unread_msgs"] = user.unread_msgs;
            res_json["picture"] = *user_db.get(user.login + "_picture");
            res_json["friends"] = user.friends;
            res_json["blacklist"] = user.blacklist;
            res_json["moderates"] = user.moderates;
            /*set<unsigned long long> chats_ids;
            for (unsigned long long msg : user.msgs) {
                chats_ids.insert(Message::get_msg(msg_db, msg).receiverId);
                chats_ids.insert(Message::get_msg(msg_db, msg).senderId);
            }
            chats_ids.erase(user.id);
            vector<unsigned long long> chats_ids_;
            chats_ids_.reserve(chats_ids.size());
            copy(chats_ids.begin(), chats_ids.end(), back_inserter(chats_ids_));
            // res_json["recent_chats"] = chats_ids_;*/
            res.body = res_json.dump();
            return res;
        }
    });
    /** Рендер страницы пользователя */
    CROW_ROUTE(app, "/profile<int>").methods("GET"_method)([&app, &user_db](const crow::request &req, long long user_id) {
        User user;
        User profile_user;
        auto res = crow::response();
        res.body = crow::mustache::load_text("profile.html");
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        try {
            user = Session::get_user(user_db, token);
        }
        catch (...) {
            // Токен оказался невалидным, обнуляем его
            ctx.set_cookie("token", "");
            res.redirect("/login");
            return res;
        }
        // Проверяем, что этот пользователь существует и этот пользователь - не отправитель запроса
        try {
            profile_user = User::get_user(user_db, user_id);
            if (profile_user.id == user.id) throw runtime_error("Отправитель запроса и есть искомый пользователь");
        }
        catch (...){
            res.redirect("/me");
            return res;
        }
        if (method_name(req.method) == "GET") {
            ctx.set_cookie("user_id", to_string(user_id));
            return res;
        }
        // Если не GET, то взаимодействуем с другим пользователем
        auto req_json = crow::json::load(req.body);
        crow::json::wvalue res_json;
        try {
            if (req_json["type"].s() == "main_info_edit") {
                user.name = req_json["name"].s();
                user.surname = req_json["surname"].s();
                user.description = req_json["description"].s();
                user.save_user(user_db);
                res_json["success"] = true;
            } else if (req_json["type"].s() == "pass_update") {
                if (user.password != req_json["password1"].s()) {
                    res_json["error"] = "password";
                } else {
                    user.password = req_json["password2"].s();
                    user.save_user(user_db);
                    res_json["success"] = true;
                }
            } else if (req_json["type"].s() == "profile_photo_update") {
                user.picture = req_json["photo"].s();
                user.save_user(user_db);
                res_json["success"] = true;
            } else if (req_json["type"].s() == "tfa_toggle") {
                user.tfa_on = req_json["check"].b();
                user.save_user(user_db);
                res_json["toggle"] = user.tfa_on;
            }
        }
        catch (const std::exception &exc) {
            cerr << exc.what() << endl;
            res_json["error"] = true;
        }
        res.body = res_json.dump();
        return res;
    });
    /** Информация о пользователе по айди */
    CROW_ROUTE(app, "/info<int>").methods("GET"_method)([&user_db](const crow::request &req, int user_id) {
        auto res = crow::response();
        crow::json::wvalue res_json;
        try {
            auto user = User::get_user(user_db, user_id);
            res_json["id"] = user.id;
            res_json["login"] = user.login;
            res_json["name"] = user.name;
            res_json["surname"] = user.surname;
            res_json["description"] = user.description;
            res_json["picture"] = *user_db.get(user.login + "_picture");
            res_json["friends"] = user.friends;
            res.body = res_json.dump();
            return res;
        }
        catch (...) {
            // произошла ошибка
            res.redirect("/login");
            return res;
        }
    });
    /** Добавить или удалить друга */
    CROW_ROUTE(app, "/friend").methods("POST"_method)([&app, &user_db](const crow::request &req){
        User user;
        auto res = crow::response();
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        try {
            user = Session::get_user(user_db, token);
        }
        catch (...) {
            // Токен оказался невалидным, обнуляем его
            ctx.set_cookie("token", "");
            res.redirect("/login");
            return res;
        }
        auto req_json = crow::json::load(req.body);
        if (req_json["method"].s() == "add"){
            // добавляем друга
            for (auto u : user.friends) if (u == req_json["user_id"].i()) throw runtime_error("Этот пользователь уже в друзьях");
            for (auto u : user.blacklist) if (u == req_json["user_id"].i()) throw runtime_error("Этот пользователь в чёрном списке");
            user.friends.push_back(req_json["user_id"].i());
            user.save_user(user_db);
        }
        else{
            // удаляем друга
            auto f = find(user.friends.begin(), user.friends.end(), req_json["user_id"].i());
            if (f != user.friends.end()) user.friends.erase(f);
            user.save_user(user_db);
        }
        crow::json::wvalue res_json;
        res_json["success"] = true;
        res.body = res_json.dump();
        return res;
    });
    /** Добавить или удалить в чс */
    CROW_ROUTE(app, "/blacklist").methods("POST"_method)([&app, &user_db](const crow::request &req){
        User user;
        auto res = crow::response();
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        try {
            user = Session::get_user(user_db, token);
        }
        catch (...) {
            // Токен оказался невалидным, обнуляем его
            ctx.set_cookie("token", "");
            res.redirect("/login");
            return res;
        }
        auto req_json = crow::json::load(req.body);
        if (req_json["method"].s() == "remove"){
            // Удаление из чс
            auto f = find(user.blacklist.begin(), user.blacklist.end(), req_json["user_id"].i());
            if (f != user.blacklist.end()) user.blacklist.erase(f);
            user.save_user(user_db);
        }
        else{
            // добавление в чс
            for (auto u : user.blacklist) if (u == req_json["user_id"].i()) throw runtime_error("Этот пользователь уже в чёрном списке");
            // Если этот пользователь в друзьях, то удаляем его
            auto f = find(user.friends.begin(), user.friends.end(), req_json["user_id"].i());
            if (f != user.friends.end()) user.friends.erase(f);
            user.blacklist.push_back(req_json["user_id"].i());
            user.save_user(user_db);
        }
        crow::json::wvalue res_json;
        res_json["success"] = true;
        res.body = res_json.dump();
        return res;
    });
    /** Отправить жалобу */
    CROW_ROUTE(app, "/add_moderation").methods("POST"_method)([&app, &user_db, &moderation_db](const crow::request &req){
        User user;
        auto res = crow::response();
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        try {
            user = Session::get_user(user_db, token);
        }
        catch (...) {
            // Токен оказался невалидным, обнуляем его
            ctx.set_cookie("token", "");
            res.redirect("/login");
            return res;
        }
        auto req_json = crow::json::load(req.body);
        for (auto u : user.moderates) if (u == req_json["user_id"].i()) throw runtime_error("Этот пользователь уже подал жалобу");
        user.moderates.push_back(req_json["user_id"].i());
        user.save_user(user_db);
        Moderation::create_moderation(moderation_db, user.id, req_json["user_id"].i());
        crow::json::wvalue res_json;
        res_json["success"] = true;
        res.body = res_json.dump();
        return res;
    });
    /** TODO: Последние посты пользователя */
    CROW_ROUTE(app, "/last_posts").methods("GET"_method)([&app, &user_db](const crow::request &req) {
        return 0;
    });
    /** Страница с друзьями */
    CROW_ROUTE(app, "/friends").methods("GET"_method)([&app, &user_db](const crow::request &req) {
        User user;
        auto res = crow::response();
        res.body = crow::mustache::load_text("friends.html");
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        try {
            Session::get_user(user_db, token);
        }
        catch (...) {
            // Токен оказался невалидным, обнуляем его
            ctx.set_cookie("token", "");
            res.redirect("/login");
            return res;
        }
        return res;
    });
    /** Страница с поиском человека */
    CROW_ROUTE(app, "/people").methods("GET"_method)([&app, &user_db](const crow::request &req){
        User user;
        auto res = crow::response();
        res.body = crow::mustache::load_text("users.html");
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        try {
            Session::get_user(user_db, token);
        }
        catch (...) {
            // Токен оказался невалидным, обнуляем его
            ctx.set_cookie("token", "");
            res.redirect("/login");
            return res;
        }
        return res;
    });
    /** Поиск по логину */
    CROW_ROUTE(app, "/search<string>").methods("GET"_method)([&user_db](const crow::request &req, const string& searched_login) {
        auto res = crow::response();
        crow::json::wvalue res_json;
        try {
            auto user = User::get_user_by_login(user_db, searched_login);
            res_json["found"] = true;
            res_json["id"] = user.id;
            res_json["login"] = user.login;
            res_json["name"] = user.name;
            res_json["surname"] = user.surname;
            res_json["description"] = user.description;
            res_json["picture"] = *user_db.get(user.login + "_picture");
            res_json["friends"] = user.friends;
            res.body = res_json.dump();
        }
        catch (...) {
            res_json["found"] = false;
        }
        res.body = res_json.dump();
        return res;
    });
    /** Рендер чата по умолчанию */
    CROW_ROUTE(app, "/chat").methods("GET"_method)([&app, &user_db](const crow::request &req) {
        User user;
        auto res = crow::response();
        res.body = crow::mustache::load_text("chat.html");
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        try {
            user = Session::get_user(user_db, token);
            ctx.set_cookie("chat_user_id", "-1");
            return res;
        }
        catch (...) {
            // Токен оказался невалидным, обнуляем его
            ctx.set_cookie("token", "");
            res.redirect("/login");
            return res;
        }
    });
    /** Рендер чата */
    CROW_ROUTE(app, "/chat/<int>").methods("GET"_method)([&app, &user_db](const crow::request &req, long long user_id) {
        User user;
        auto res = crow::response();
        res.body = crow::mustache::load_text("chat.html");
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        try {
            user = Session::get_user(user_db, token);
            auto user_chat = User::get_user(user_db, user_id);
            if (find(user_chat.blacklist.begin(), user_chat.blacklist.end(), user.id) != user_chat.blacklist.end()){
                // Если выбранный нами пользователь добавил нас в ЧС, то перенаправляем на обычную страницу чата
                res.redirect("/chat");
                return res;
            }
            if (find(user.blacklist.begin(), user.blacklist.end(), user_chat.id) != user.blacklist.end()){
                // Если мы добавили этого пользователя в ЧС, то мы не можем написать ему сообщение
                res.redirect("/chat");
                return res;
            }
            // В противном случае рендерим страницу и обнуляем количество непрочитанных сообщений
            user.unread_msgs = 0;
            user.save_user(user_db);
            ctx.set_cookie("chat_user_id", to_string(user_chat.id));
            return res;
        }
        catch (...) {
            // Токен оказался невалидным, обнуляем его
            ctx.set_cookie("token", "");
            res.redirect("/login");
            return res;
        }
    });
    /** Рендер чата по логину */
    CROW_ROUTE(app, "/chat/<str>").methods("GET"_method)([&app, &user_db](const crow::request &req, const string& user_login) {
        auto res = crow::response();
        try {
            auto user = User::get_user_by_login(user_db, user_login);
            res.redirect("/chat/"+ to_string(user.id));
        }
        catch (...){
            res.redirect("/chat");
        }
        return res;
    });
    /** Последние сообщения с пользователем */
    CROW_ROUTE(app, "/chat_msg/<int>").methods("GET"_method, "POST"_method)([&app, &user_db, &msg_db](const crow::request &req, long long user_id) {
        User user;
        User user_chat;
        auto res = crow::response();
        crow::json::wvalue res_json;
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        user = Session::get_user(user_db, token);
        user_chat = User::get_user(user_db, user_id);
        if(method_name(req.method) == "GET"){
            // Возвращаем все текущие сообщения
            vector<u_int64_t> msgs_to_return;
            reverse(user.msgs.begin(), user.msgs.end());
            for (auto msg: user.msgs) {
                auto tmp = Message::get_msg(msg_db, msg);
                if (tmp.senderId == user_chat.id || tmp.receiverId == user_chat.id){
                    msgs_to_return.push_back(msg);
                }
            }
            res_json["msgs"] = msgs_to_return;
        }
        else{
            // Отправляем сообщение, ставим реакцию, редактируем или переводим деньги
            auto req_json = crow::json::load(req.body);
            if (req_json["type"].s() == "send"){
                // Если это реплай, то назначаем соответствующий параметр
                Message::send_msg(msg_db, user_db, req_json["msg_text"].s(), user.id, user_chat.id, 0, 0);
            }
            else if (req_json["type"].s() == "reaction_add"){
                auto msg = Message::get_msg(msg_db, req_json["msg_id"].i());
                msg.reaction = req_json["reaction"].s();
                msg.save_msg(msg_db);
            }
            else if (req_json["type"].s() == "reaction_cancel"){
                auto msg = Message::get_msg(msg_db, req_json["msg_id"].i());
                msg.reaction = "";
                msg.save_msg(msg_db);
            }
            else if (req_json["type"].s() == "edit"){
                auto msg = Message::get_msg(msg_db, req_json["msg_id"].i());
                msg.edited = true;
                msg.msg = req_json["msg"].s();
                msg.save_msg(msg_db);
            }
            res_json["success"] = true;
        }
        res.body = res_json.dump();
        return res;
    });
    /** Получить информацию о сообщении */
    CROW_ROUTE(app, "/msg_info/<int>").methods("GET"_method)([&app, &user_db, &msg_db](const crow::request &req, long long msg_id) {
        User user;
        Message msg;
        auto res = crow::response();
        crow::json::wvalue res_json;
        auto &ctx = app.get_context<crow::CookieParser>(req);
        string token = ctx.get_cookie("token");
        try {
            user = Session::get_user(user_db, token);
        }
        catch (...) {
            // Токен оказался невалидным, обнуляем его
            ctx.set_cookie("token", "");
            res.redirect("/login");
            return res;
        }
        msg = Message::get_msg(msg_db, msg_id);
        res_json["id"] = msg.id;
        res_json["msg"] = msg.msg;
        res_json["senderId"] = msg.senderId;
        res.body = res_json.dump();
        return res;
    });



    // TODO: перейти от использования регулярного опроса к использованию веб-сокетов
    /*
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
            .onmessage([&](crow::websocket::connection &сon, const string &data, bool is_binary) {
                lock_guard<mutex> _(mtx);
                for (auto u: users_connections)
                    if (is_binary)
                        u->send_binary(data);
                    else
                        u->send_text(data);
            });
    */
    // Вариант для ssl
    // app.bindaddr(192.168.1.2).port(443).ssl_file("certfile.crt","keyfile.key").multithreaded().run();
    app.port(9080).multithreaded().run();
    return 0;
}