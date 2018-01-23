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

using namespace std;


void send_success(int sockfd)
{
    string msg =
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html; encoding=utf8\n"
        "Content-Length: 53\n"
        "Connection: close\n\n"
        "<html><head></head><body><p>Success</p></body></html>";
    send(sockfd, msg.c_str(), msg.length(), 0);
}


map<string,string> *get_params(string req)
{
    map<string,string> *req_map = new map<string,string>();

    vector<string> split_vector;
    boost::split(split_vector, req, boost::is_any_of("\r\n"), boost::token_compress_on);

    for (vector<string>::iterator line_iter = split_vector.begin(); line_iter != split_vector.end(); ++line_iter)
    {
        string line = *line_iter;
        //cout << "Request line: " << line << endl;
        if (regex_match(line, regex("GET /.*"))) { // can require path here
            vector<string> method_path_params_version_vector;
            boost::split(method_path_params_version_vector, line, boost::is_any_of(" "), boost::token_compress_on);
            if (method_path_params_version_vector.size() >= 2)
            {
                string path_params = method_path_params_version_vector.at(1);
                size_t param_start = path_params.find_first_of("?", 0);
                if (param_start == string::npos)
                {
                    cout << "Request had no parameters" << endl;
                    break;
                }
                string params = path_params.substr(param_start+1, string::npos);
                
                vector<string> param_vector;
                boost::split(param_vector, params, boost::is_any_of("&"), boost::token_compress_on);
                for (vector<string>::iterator param_iter = param_vector.begin(); param_iter != param_vector.end(); ++param_iter) {
                    string param = *param_iter;
                    //cout << "Param: " << param << endl;
                    vector<string> key_value_vector;
                    boost::split(key_value_vector, param, boost::is_any_of("="), boost::token_compress_on);
                    if (key_value_vector.size() == 2)
                    {
                        //cout << "Param pair: " << key_value_vector.at(0) << " " << key_value_vector.at(1) << endl;
                        req_map->insert(pair<string,string>(key_value_vector.at(0), key_value_vector.at(1)));
                    }
                    else if (key_value_vector.size() == 1)
                    {
                        cout << key_value_vector.at(1) << endl;
                        req_map->insert(pair<string,string>(key_value_vector.at(0), ""));
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
    ((string*)s)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

/* TODO REMOVE */
struct data {
  char trace_ascii; /* 1 or 0 */ 
};
 
static
void dump(const char *text,
          FILE *stream, unsigned char *ptr, size_t size,
          char nohex)
{
  size_t i;
  size_t c;
 
  unsigned int width = 0x10;
 
  if(nohex)
    /* without the hex output, we can fit more on screen */ 
    width = 0x40;
 
  fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n",
          text, (long)size, (long)size);
 
  for(i = 0; i<size; i += width) {
 
    fprintf(stream, "%4.4lx: ", (long)i);
 
    if(!nohex) {
      /* hex not disabled, show it */ 
      for(c = 0; c < width; c++)
        if(i + c < size)
          fprintf(stream, "%02x ", ptr[i + c]);
        else
          fputs("   ", stream);
    }
 
    for(c = 0; (c < width) && (i + c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */ 
      if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
         ptr[i + c + 1] == 0x0A) {
        i += (c + 2 - width);
        break;
      }
      fprintf(stream, "%c",
              (ptr[i + c] >= 0x20) && (ptr[i + c]<0x80)?ptr[i + c]:'.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */ 
      if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stream); /* newline */ 
  }
  fflush(stream);
}
 
static
int my_trace(CURL *handle, curl_infotype type,
             char *data, size_t size,
             void *userp)
{
  struct data *config = (struct data *)userp;
  const char *text;
  (void)handle; /* prevent compiler warning */ 
 
  switch(type) {
  case CURLINFO_TEXT:
    fprintf(stderr, "== Info: %s", data);
    /* FALLTHROUGH */ 
  default: /* in case a new one is introduced to shock us */ 
    return 0;
 
  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case CURLINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  }
 
  dump(text, stderr, (unsigned char *)data, size, config->trace_ascii);
  return 0;
}

/* TODO END REMOVE */



string *get_access_token(string authorization_code)
{
    CURL *curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    string *response = new string();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, "https://www.googleapis.com/oauth2/v4/token");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _curl_writefunction_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
        //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        
        //struct data config;
        //config.trace_ascii = 1;
        //curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
        //curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &config);

        std::stringstream fields;// = new std::stringstream();
        fields << "code=" << curl_easy_escape(curl, authorization_code.c_str(), 0);
        fields << "&client_id=" << curl_easy_escape(curl, XXX, 0);
        fields << "&client_secret=" << curl_easy_escape(curl, XXX, 0);
        fields << "&redirect_uri=" << curl_easy_escape(curl, "http://localhost:8080", 0);
        fields << "&grant_type=" << curl_easy_escape(curl, "authorization_code", 0);
        string *fields_string = new string(fields.str()); // Must be heap allocated. curl's COPYPOSTFIELDS didn't work
        cout << "Post fields " << *fields_string << endl;
        
        //struct curl_slist* slist = NULL;
        //slist = curl_slist_append(slist, "Content-Type: application/x-www-form-urlencoded");
        //slist = curl_slist_append(slist, "Accept: application/json");
        //slist = curl_slist_append(slist, "User-Agent: curl");
        //curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
        
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, fields_string->length());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields_string->c_str());

        cout << "Performing curl" << endl;
        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
        delete fields_string;
    }
    curl_global_cleanup();

    cout << *response << endl;
    return response;
}



int main(int argc, char **argv)
{
    int sockfd;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    //fcntl(sockfd, F_SETFL, O_NONBLOCK);

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(8080);
    bind(sockfd, (struct sockaddr *)&server_address, sizeof(server_address));
    listen(sockfd, 1);
    while (1)
    {
        socklen_t socksize = sizeof(client_address);
        int conn_sock_fd = accept(sockfd, (struct sockaddr *)&client_address, &socksize);

        const size_t BUF_LEN = 2048;
        char buf[BUF_LEN+1]; buf[BUF_LEN] = {0x0};
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(conn_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        string message = string("");
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
            message.append(buf);

        }
        cout << message << endl;
        map<string,string> *param_map = get_params(message);
        if (param_map->find("code") != param_map->end())
        {
            string authorization_code = param_map->at("code");
            cout << "Using authorization code to retrieve OAuth2 access token" << endl;
            string *access_token_response = get_access_token(authorization_code);
            cout << *access_token_response;
        }
        else
        {
            cout << "Request did not contain an authorization code" << endl;
        }
        
        delete param_map;
    } // end while
} // end main


