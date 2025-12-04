// transport.cpp
#include "transport.h"
#include <curl/curl.h>
#include <json/json.h> // or construct JSON by hand if no lib

bool send_ciphertext_http(const std::string &url, const std::string &message_b64, int priority, std::string &err) {
    CURL *curl = curl_easy_init();
    if (!curl) { err = "curl init failed"; return false; }
    Json::Value root;
    root["message"] = message_b64;
    root["priority"] = priority;
    Json::StreamWriterBuilder w;
    std::string body = Json::writeString(w, root);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        err = curl_easy_strerror(res);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return true;
}
