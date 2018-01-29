#include <iostream>
#include <string>
#include <sstream>
#include <map>
#include <regex>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <curl/curl.h>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/format.hpp>

//using namespace std;

std::string *curl_post(std::string, std::string *);
std::string *curl_get(std::string, std::string *);

void send_success(int sockfd)
{
    std::string msg =
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html; encoding=utf8\n"
        "Content-Length: 53\n"
        "Connection: close\n\n"
        "<html><head></head><body><p>Success</p></body></html>";
    send(sockfd, msg.c_str(), msg.length(), 0);
}

/* Given a fully qualified url to a discovery document for an OpenID Identity Provider,
 * send a GET request for that document and put it into a boost ptree.
 */
boost::property_tree::ptree *get_provider_metadata(std::string provider_metadata_url)
{
    boost::property_tree::ptree *metadata_tree = new boost::property_tree::ptree();
    std::string params = "";
    std::string *metadata_string = curl_get(provider_metadata_url, &params);
    cout << "Provider metadata: " << endl << *metadata_string << endl;
    stringstream metadata_stream(*metadata_string);
    
    boost::property_tree::read_json(metadata_stream, *metadata_tree);
   
    const char *required_fields[] = {
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "scopes_supported",
        "response_types_supported",
        "claims_supported"};
    vector<std::string> metadata_required(required_fields, end(required_fields));
    for (vector<std::string>::iterator field_iter = metadata_required.begin(); field_iter != metadata_required.end(); ++field_iter)
    {
        if (metadata_tree->find(*field_iter) == metadata_tree->not_found())
        {
            cout << "Metadata tree missing required field: " << *field_iter << endl;
            delete metadata_tree;
            metadata_tree = NULL;
            break;
        }
    }
 
    delete metadata_string;
    return metadata_tree;
}

// TODO
// static vector<boost::property_tree::ptree> provider_discovery_metadata_cache;

bool get_provider_metadata_field(std::string provider_metadata_url, const std::string fieldname, std::string& value)
{
    boost::property_tree::ptree *metadata_tree = get_provider_metadata(provider_metadata_url);
    if (metadata_tree->find(fieldname) != metadata_tree->not_found())
    {
        value = metadata_tree->get<std::string>(fieldname);
        return true;
    }
    else
    {
        return false;
    }
}


/* Takes a GET request string. This is the literal string representation of the request.
 * Looks for the line with the request path, and splits it up into pair<key, value> for each request parameter
 * If the key has no value, the value part of the pair is left as an empty string. 
 * Returns a map<string,string> of each request parameter
 */
std::map<std::string,std::string> *get_params(std::string req)
{
    std::map<std::string,std::string> *req_map = new std::map<std::string,std::string>();
    vector<string> split_vector;
    boost::split(split_vector, req, boost::is_any_of("\r\n"), boost::token_compress_on);
    // iterate over lines in the request string
    for (vector<std::string>::iterator line_iter = split_vector.begin(); line_iter != split_vector.end(); ++line_iter)
    {
        std::string line = *line_iter;
        //cout << "Request line: " << line << endl;
        if (regex_match(line, regex("GET /.*"))) { // can require path here
            vector<std::string> method_path_params_version_vector;
            boost::split(method_path_params_version_vector, line, boost::is_any_of(" "), boost::token_compress_on);
            if (method_path_params_version_vector.size() >= 2)
            {
                std::string path_params = method_path_params_version_vector.at(1);
                size_t param_start = path_params.find_first_of("?", 0);
                if (param_start == std::string::npos)
                {
                    cout << "Request had no parameters" << endl;
                    break;
                }
                std::string params = path_params.substr(param_start+1, std::string::npos);
                
                vector<std::string> param_vector;
                boost::split(param_vector, params, boost::is_any_of("&"), boost::token_compress_on);
                // iterate over parameters in the request path
                for (vector<std::string>::iterator param_iter = param_vector.begin(); param_iter != param_vector.end(); ++param_iter) {
                    std::string param = *param_iter;
                    vector<std::string> key_value_vector;
                    // split the parameter into [name, value], or [name] if no value exists
                    boost::split(key_value_vector, param, boost::is_any_of("="), boost::token_compress_on);
                    if (key_value_vector.size() == 2)
                    {
                        req_map->insert(pair<std::string,std::string>(key_value_vector.at(0), key_value_vector.at(1)));
                    }
                    else if (key_value_vector.size() == 1)
                    {
                        req_map->insert(pair<std::string,std::string>(key_value_vector.at(0), ""));
                    }
                }
            }
            else
            {
                cout << "GET line had " << method_path_params_version_vector.size() << " terms" << endl;
                // error
            }
        }
    }

    return req_map;
}

static size_t _curl_writefunction_callback(void *contents, size_t size, size_t nmemb, void *s)
{
    ((std::string*)s)->append((char*)contents, size * nmemb);
    return size * nmemb;
}


/* Return a string response from a post call
 * token_endpoint_url = "https://www.googleapis.com/oauth2/v4/token"
 * client_id = "118582272506-6vm4rruieahekajob0tghgdf3iogtdgt.apps.googleusercontent.com"
 * client_secret = "el7Fkt1q4KMozJ-M9uNJebWz"
 * redirect_uri = "http://localhost:8080"
 * authorization_code = <different per authorization request>
 */
std::string *get_access_token(std::string token_endpoint_url, 
                              std::string authorization_code, 
                              std::string client_id, 
                              std::string client_secret, 
                              std::string redirect_uri)
{
    std::stringstream fields;
    fields << "code=" << authorization_code;
    fields << "&client_id=" << client_id;
    fields << "&client_secret=" << client_secret;
    fields << "&redirect_uri=" << redirect_uri;
    fields << "&grant_type=" << "authorization_code";
    std::string *field_str = new std::string(fields.str());
    std::string *response = curl_post(token_endpoint_url, field_str);
    delete field_str;
    return response;
}


std::string *curl_post(std::string url, std::string *fields)
{
    CURL *curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    std::string *response = new std::string();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _curl_writefunction_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, fields->length());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields->c_str());

        cout << "Performing curl" << endl;
        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return response;
}

std::string *curl_get(std::string url, std::string *params)
{
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    std::string *response = new std::string();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _curl_writefunction_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return response;
}

std::string *accept_request(int portno)
{
    int sockfd;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(8080);
    bind(sockfd, (struct sockaddr *)&server_address, sizeof(server_address));
    listen(sockfd, 1);
    std::string *message = new std::string("");
    
    // set up connection socket
    socklen_t socksize = sizeof(client_address);
    int conn_sock_fd = accept(sockfd, (struct sockaddr *)&client_address, &socksize);
    const size_t BUF_LEN = 2048;
    char buf[BUF_LEN+1]; buf[BUF_LEN] = 0x0;
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(conn_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    while (1)
    {
        int received_len = recv(conn_sock_fd, buf, BUF_LEN, 0);
        cout << "Received " << received_len << endl;
        if (received_len == -1)
        {
            // EAGAIN EWOULDBLOCK
            cout << "Timeout reached" << endl;
            send_success(conn_sock_fd);
            break;
        }
        if (received_len == 0)
        {
            cout << "Closing connection" << endl;
            send_success(conn_sock_fd);
            close(conn_sock_fd);
            break;
        }
        message->append(buf); 
    }
    close(sockfd);
    return message;
}

int main(int argc, char **argv)
{
    boost::property_tree::ptree *metadata_tree = get_provider_metadata("https://accounts.google.com/.well-known/openid-configuration");
    if ( !metadata_tree )
    {
        return 1;
    }
    std::string provider_authorization_endpoint = metadata_tree->get<std::string>("authorization_endpoint");
    std::string provider_token_endpoint = metadata_tree->get<std::string>("token_endpoint");
    std::string provider_userinfo_endpoint = metadata_tree->get<std::string>("userinfo_endpoint");

    std::string client_id = "118582272506-6vm4rruieahekajob0tghgdf3iogtdgt.apps.googleusercontent.com";
    std::string client_secret = "el7Fkt1q4KMozJ-M9uNJebWz";

    std::string authorize_url_fmt = "%s?response_type=%s&scope=%s&client_id=%s&redirect_uri=%s";
    boost::format fmt(authorize_url_fmt);
    fmt 
                            % provider_authorization_endpoint
                            % "code"
                            % "openid"
                            % client_id
                            % "http://localhost:8080";
    std::string authorize_url = fmt.str();

    std::cout << "Waiting for OpenID provider authorization...\n" << authorize_url << std::endl;

    while (1)
    {
        std::string *message = accept_request(8080);
        std::cout << *message << std::endl;
        std::map<std::string,std::string> *param_map = get_params(*message);
        if (param_map->find("code") != param_map->end())
        {
            std::string authorization_code = param_map->at("code");
            //cout << "Using authorization code to retrieve OAuth2 access token" << endl;
            std::string *access_token_response = get_access_token(
                                                "https://www.googleapis.com/oauth2/v4/token",
                                                authorization_code,
                                                "118582272506-6vm4rruieahekajob0tghgdf3iogtdgt.apps.googleusercontent.com",
                                                "el7Fkt1q4KMozJ-M9uNJebWz",
                                                "http://localhost:8080");

            std::cout << *access_token_response;
            std::stringstream response_stream(*access_token_response);
            
            boost::property_tree::ptree response_tree;
            boost::property_tree::read_json(response_stream, response_tree);
            if (response_tree.find("access_token") == response_tree.not_found() 
                  || response_tree.find("id_token") == response_tree.not_found()
                  || response_tree.find("expires_in") == response_tree.not_found()) 
            {
                std::cout << "Token response missing required fields (access_token, expires_in, id_token)" << std::endl;
            }
            else
            {
                std::string id_token = response_tree.get<std::string>("id_token");
                std::string access_token = response_tree.get<std::string>("access_token");
                std::string expires_in = response_tree.get<std::string>("expires_in");
                cout << "id_token: " << id_token << endl;
                // TODO base64 decode and validate fields 
                // https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                std::cout << "access_token: " << access_token << std::endl;
                std::cout << "expires_in: " << expires_in << std::endl;
            }
            delete access_token_response;
        }
        else
        {
            std::cout << "Request did not contain an authorization code" << std::endl;
        }
        
        delete param_map;
    } // end while
} // end main


