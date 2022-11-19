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
