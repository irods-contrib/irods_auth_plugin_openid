#include <boost/property_tree/ptree.hpp>

boost::property_tree::ptree *get_provider_metadata(std::string provider_metadata_url);

void send_success(int sockfd);
std::string *accept_request(int portno);

std::map<std::string,std::string> *get_params(std::string req);

std::string *get_access_token(std::string token_endpoint_url,
                         std::string authorization_code,
                         std::string client_id,
                         std::string client_secret,
                         std::string redirect_uri);

boost::property_tree::ptree *get_provider_metadata(std::string provider_metadata_url);
bool get_provider_metadata_field(std::string provider_metadata_url, const std::string fieldname, std::string& value);

