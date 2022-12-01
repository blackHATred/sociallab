#include <cctype>
#include <iomanip>
#include <iostream>
#include <string>
#include <codecvt>
#include <regex>
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

map<string, string> down_up_abc = {{"а", "А"},{"б", "Б"},{"в", "В"},{"г", "Г"},{"д", "Д"},{"е", "Е"},{"ё", "Ё"},{"ж", "Ж"},{"з", "З"},{"и", "И"},{"й", "Й"},{"к", "К"},{"л", "Л"},{"м", "М"},{"н", "Н"},{"о", "О"},{"п", "П"},{"р", "Р"},{"с", "С"},{"т", "Т"},{"у", "У"},{"ф", "Ф"},{"х", "Х"},{"ц", "Ц"},{"ч", "Ч"},{"ш", "Ш"},{"щ", "Щ"},{"ъ", "Ъ"},{"ы", "Ы"},{"ь", "Ь"},{"э", "Э"},{"ю", "Ю"},{"я", "Я"},{"a", "A"},{"b", "B"},{"c", "C"},{"d", "D"},{"e", "E"},{"f", "F"},{"g", "G"},{"h", "H"},{"i", "I"},{"j", "J"},{"k", "K"},{"l", "L"},{"m", "M"},{"n", "N"},{"o", "O"},{"p", "P"},{"q", "Q"},{"r", "R"},{"s", "S"},{"t", "T"},{"u", "U"},{"v", "V"},{"w", "W"},{"x", "X"},{"y", "Y"},{"z", "Z"}};
string to_upper(string s){
    for (const auto& kv : down_up_abc) s = regex_replace(s, regex(kv.first), kv.second);
    return s;
}

map<string, string> up_down_abc = {{"А", "а"},{"Б", "б"},{"В", "в"},{"Г", "г"},{"Д", "д"},{"Е", "е"},{"Ё", "ё"},{"Ж", "ж"},{"З", "з"},{"И", "и"},{"Й", "й"},{"К", "к"},{"Л", "л"},{"М", "м"},{"Н", "н"},{"О", "о"},{"П", "п"},{"Р", "р"},{"С", "с"},{"Т", "т"},{"У", "у"},{"Ф", "ф"},{"Х", "х"},{"Ц", "ц"},{"Ч", "ч"},{"Ш", "ш"},{"Щ", "щ"},{"Ъ", "ъ"},{"Ы", "ы"},{"Ь", "ь"},{"Э", "э"},{"Ю", "ю"},{"Я", "я"},{"A", "a"},{"B", "b"},{"C", "c"},{"D", "d"},{"E", "e"},{"F", "f"},{"G", "g"},{"H", "h"},{"I", "i"},{"J", "j"},{"K", "k"},{"L", "l"},{"M", "m"},{"N", "n"},{"O", "o"},{"P", "p"},{"Q", "q"},{"R", "r"},{"S", "s"},{"T", "t"},{"U", "u"},{"V", "v"},{"W", "w"},{"X", "x"},{"Y", "y"},{"Z", "z"}};
string to_lower(string s){
    for (const auto& kv : up_down_abc) s = regex_replace(s, regex(kv.first), kv.second);
    return s;
}

string to_title(string s){
    s = to_lower(s);
    //s = s.replace(s.begin(), s.begin()+1, to_upper(s.substr(0, 1)));
    s[0] = to_upper(s.substr(0, 1)).at(0);
    int cplen = 1;
    if((s[0] & 0xf8) == 0xf0) cplen = 4;
    else if((s[0] & 0xf0) == 0xe0) cplen = 3;
    else if((s[0] & 0xe0) == 0xc0) cplen = 2;
    if((0 + cplen) > s.length()) cplen = 1;
    s = s.replace(s.begin(), s.begin()+cplen, to_upper(s.substr(0, cplen)));

    return s;
}
