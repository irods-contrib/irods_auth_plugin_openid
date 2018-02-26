//#define USE_SSL 1 (libpam.cpp)
#include "sslSockComm.h"

#include "authCheck.h"
#include "authPluginRequest.h"
#include "authRequest.h"
#include "authResponse.h"
#include "authenticate.h"
#include "genQuery.h"
#include "irods_auth_constants.hpp"
#include "irods_auth_plugin.hpp"
//#include "irods_openid_object.hpp"
#include "irods_client_server_negotiation.hpp"
#include "irods_configuration_keywords.hpp"
#include "irods_error.hpp"
#include "irods_generic_auth_object.hpp"
#include "irods_kvp_string_parser.hpp"
#include "irods_server_properties.hpp"
#include "irods_environment_properties.hpp"
#include "irods_stacktrace.hpp"
#include "miscServerFunct.hpp"
#include "rodsErrorTable.h"
#include "rodsLog.h"
#include "irods_string_tokenize.hpp"

#ifdef RODS_SERVER
#include "rsGenQuery.hpp"
#include "rsAuthCheck.hpp"
#include "rsAuthResponse.hpp"
#include "rsAuthRequest.hpp"
#include "rsModAVUMetadata.hpp"
#include "rsSimpleQuery.hpp"
#endif

#include <openssl/md5.h>
#include <gssapi.h>
#include <string>

///OPENID includes
#include <sstream>
#include <map>
#include <thread>
#include <condition_variable>
#include <mutex>
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

#include "base64.h"
///END OPENID includes
///DECLARATIONS

#ifdef RODS_SERVER
// =-=-=-=-=-=-=-
// NOTE:: this needs to become a property
// Set requireServerAuth to 1 to fail authentications from
// un-authenticated Servers (for example, if the LocalZoneSID
// is not set)
static const int requireServerAuth = 0;
//static int openidAuthReqStatus = 0;
//static int openidAuthReqError = 0;
//static const int openidAuthErrorSize = 1000;
//static char openidAuthReqErrorMsg[openidAuthErrorSize];
#endif

static const std::string AUTH_OPENID_SCHEME("openid");

boost::property_tree::ptree *get_provider_metadata(std::string provider_metadata_url);

void send_success(int sockfd);
std::string *accept_request(int portno);

std::map<std::string,std::string> *get_params(std::string req);

bool get_access_token(std::string token_endpoint_url,
                         std::string authorization_code,
                         std::string client_id,
                         std::string client_secret,
                         std::string redirect_uri,
                         std::string* response);

bool get_provider_metadata_field(std::string provider_metadata_url, const std::string fieldname, std::string& value);
irods::error generate_authorization_url(std::string& urlBuf);
irods::error openid_authorize(std::string& id_token, std::string& access_token, std::string& expires_in, std::string& refresh_token);
// OPENID helper methods
bool curl_post(std::string url, std::string *fields, std::vector<std::string> *headers, std::string *response);
std::string *curl_get(std::string url, std::string *fields);

///END DECLARATIONS

#define OPENID_COMM_PORT 1357
#define OPENID_ACCESS_TOKEN_KEY "access_token"
#define OPENID_ID_TOKEN_KEY "id_token"
#define OPENID_EXPIRY_KEY "expiry"
#define OPENID_REFRESH_TOKEN_KEY "refresh_token"
#define OPENID_USER_METADATA_SESSION_PREFIX "openid_sess_"
#define OPENID_USER_METADATA_REFRESH_TOKEN_KEY "openid_refresh_token"

/*
    Opens a socket connection to the irods_host set in ~/.irods/irods_environment.json
    on port OPENID_COMM_PORT.  Reads two messages. Messages start with 4 bytes specifying the length,
    followed immediately by the message. Bytes for the length are the raw bytes of an int, in order. (no hton/ntoh)

    The first message is the authorization url. This is printed to stdout.  The user must navigate to this url in
    order to authorize the server to communicate with the OIDC provider. 

    The server will wait for the callback request from this url.  After receiving the callback, it will read the tokens
    from the request and send the email and a session token in a 2nd and 3rd message respectively.

    TODO refactor the repetitive read code
*/
void read_from_server(std::string* user_name, std::string* session_token) {
    std::cout << "entering read_from_server" << std::endl;
    int sockfd, n_bytes;
    struct sockaddr_in serv_addr;
    struct hostent* server;
    const int READ_LEN = 256;
    char buffer[READ_LEN + 1];
    memset( buffer, 0, READ_LEN + 1 );
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if ( sockfd < 0 ) {
        perror( "socket" );
        return;
    }
    std::string irods_env_host = irods::get_environment_property<std::string&>("irods_host"); // TODO error check
    server = gethostbyname( irods_env_host.c_str() ); // TODO this only handles hostnames, not IP addresses. ok?
    if ( server == NULL ) {
        fprintf( stderr, "No host found for host: %s\n", irods_env_host.c_str() ); 
        return;
    }
    memset( &serv_addr, 0, sizeof( serv_addr ) );
    serv_addr.sin_family = AF_INET;
    memcpy( server->h_addr, &serv_addr.sin_addr.s_addr, server->h_length );
    serv_addr.sin_port = htons( OPENID_COMM_PORT );
    if ( connect( sockfd, (struct sockaddr*)&serv_addr, sizeof( serv_addr ) ) < 0 ) {
        perror( "connect" );
        return;
    }
    int data_len = 0;
    int total_bytes = 0;

    // read first 4 bytes (data length)
    std::string authorization_url_buf;
    read( sockfd, &data_len, sizeof( data_len ) );
    memset( buffer, 0, READ_LEN );
    // read that many bytes into our buffer, which contains the Authorization url
    while ( total_bytes < data_len ) {
        int bytes_remaining = data_len - total_bytes;
        if ( bytes_remaining < READ_LEN ) {
            // can read rest of data in one go
            n_bytes = read( sockfd, buffer, bytes_remaining );
        }
        else {
            // read max bytes into buffer
            n_bytes = read( sockfd, buffer, READ_LEN );
        }
        if ( n_bytes == -1 ) {
            // error reading
            break;
        }
        if ( n_bytes == 0 ) {
            // no more data
            break;
        }
        //std::cout << "received " << n_bytes << " bytes: " << buffer << std::endl;
        //for ( int i = 0; i < n_bytes; i++ ) {
        //    printf( "%02X", buffer[i] );
        //}
        //printf( "\n" );
        authorization_url_buf.append( buffer );
        total_bytes += n_bytes;
        memset( buffer, 0, READ_LEN );
    }
    // finished reading authorization url
    // if the auth url is "true", session is already authorized, no user action needed
    // TODO find better way to signal a valid session, debug issue with using empty message as url
    if ( authorization_url_buf.compare("true") == 0 ) {
        std::cout << "Session is valid" << std::endl;
    }
    else {
        std::cout << "OpenID Authorization URL: \n" << authorization_url_buf << std::endl;
    }

    // wait for username message now
    read( sockfd, &data_len, sizeof( data_len ) );
    total_bytes = 0;
    memset( buffer, 0, READ_LEN );
    while ( total_bytes < data_len ) {
        int bytes_remaining = data_len - total_bytes;
        if ( bytes_remaining < READ_LEN ) {
            // can read rest of data in one go
            n_bytes = read( sockfd, buffer, bytes_remaining );
        }
        else {
            // read max bytes into buffer
            n_bytes = read( sockfd, buffer, READ_LEN );
        }
        if ( n_bytes == -1 ) {
            // error reading
            break;
        }
        if ( n_bytes == 0 ) {
            // no more data
            break;
        }
        //std::cout << "received " << n_bytes << " bytes: " << buffer << std::endl;
        //for ( int i = 0; i < n_bytes; i++ ) {
        //    printf( "%02X", buffer[i] );
        //}
        //printf( "\n" );
        user_name->append( buffer );
        total_bytes += n_bytes;
        memset( buffer, 0, READ_LEN );
    } // finished reading username string from server
    std::cout << "read user_name: " << *user_name << std::endl;

    // wait for session token now
    read( sockfd, &data_len, sizeof( data_len ) );
    total_bytes = 0;
    memset( buffer, 0, READ_LEN );
    while ( total_bytes < data_len ) {
        int bytes_remaining = data_len - total_bytes;
        if ( bytes_remaining < READ_LEN ) {
            // can read rest of data in one go
            n_bytes = read( sockfd, buffer, bytes_remaining );
        }
        else {
            // read max bytes into buffer
            n_bytes = read( sockfd, buffer, READ_LEN );
        }
        if ( n_bytes == -1 ) {
            // error reading
            break;
        }
        if ( n_bytes == 0 ) {
            // no more data
            break;
        }
        //std::cout << "received " << n_bytes << " bytes: " << buffer << std::endl;
        //for ( int i = 0; i < n_bytes; i++ ) {
        //    printf( "%02X", buffer[i] );
        //}
        //printf( "\n" );
        session_token->append( buffer );
        total_bytes += n_bytes;
        memset( buffer, 0, READ_LEN );
    } // finished reading session from server
    std::cout << "read session token: " << *session_token << std::endl;

    close( sockfd );
    std::cout << "leaving read_from_server" << std::endl;
}


irods::error openid_auth_establish_context(
    irods::plugin_context& _ctx ) {
    //std::cout << "entering openid_auth_establish_context" << std::endl;
    irods::error result = SUCCESS();
    irods::error ret;

    ret = _ctx.valid<irods::generic_auth_object>();
    if ( !ret.ok()) {
        return ERROR(SYS_INVALID_INPUT_PARAM, "Invalid plugin context.");
    }
    irods::generic_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::generic_auth_object>( _ctx.fco() );

    //std::cout << "leaving openid_auth_establish_context" << std::endl;
    return ret;
}

irods::error openid_auth_client_start(
    irods::plugin_context& _ctx,
    rcComm_t*              _comm,
    const char*            _context_string)
{
    std::cout << "entering openid_auth_client_start" << std::endl;
    irods::error result = SUCCESS();
    irods::error ret;

    ret = _ctx.valid<irods::generic_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context.") ).ok() ) {
        if ( ( result = ASSERT_ERROR( _comm != NULL, SYS_INVALID_INPUT_PARAM, "Null rcComm_t pointer." ) ).ok() ) {
            irods::generic_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::generic_auth_object>( _ctx.fco() );
            
            // set the user name from the conn
            ptr->user_name( _comm->proxyUser.userName );
            
            // se the zone name from the conn
            ptr->zone_name( _comm->proxyUser.rodsZone );

            // set the socket from the conn
            ptr->sock( _comm->sock );
            char pwBuf[MAX_PASSWORD_LEN + 1];
            memset( pwBuf, 0, MAX_PASSWORD_LEN + 1);
            int getPwError = obfGetPw( pwBuf );
            if ( getPwError || strlen( (const char*)pwBuf ) == 0 ) {
                std::cout << "No cached password file" << std::endl;
            }
            else {
                std::cout << "Password file contains: " << pwBuf << std::endl;
                
                // set the password in the context string
                irods::kvp_map_t ctx_map;
                ctx_map[irods::AUTH_PASSWORD_KEY] = pwBuf;
                std::string new_context_str = irods::escaped_kvp_string( ctx_map );
                std::cout << "setting context: " << new_context_str << std::endl;
                ptr->context( new_context_str );
            }
            
        }
    }
    std::cout << "leaving openid_auth_client_start" << std::endl;
    return result;
}


/*
    Base64 encode a string and put it in the out reference. Handle padding and length nicely.
*/
irods::error _base64_easy_encode( std::string in, std::string& out )
{
    unsigned long base64_len = (int)( in.size() * 4/3 + 1);
    
    // include room for pad
    if ( base64_len % 4 != 0 ) {
        base64_len += 4 - ( base64_len % 4 );
    }
    // include room for null terminator
    base64_len += 1;

    char base64_buf[ base64_len ];
    memset( base64_buf, 0, base64_len );
    std::cout << "in: " << in << std::endl;
    std::cout << "inlen: " << in.size() << std::endl;
    std::cout << "out max len: " << base64_len << std::endl;
    int ret = base64_encode( (const unsigned char*)in.c_str(), in.size(), (unsigned char*)base64_buf, &base64_len );
    if ( ret != 0 ) {
        std::stringstream err_stream;
        err_stream << "base64_encode failed with: " << ret;
        std::cout << err_stream.str() << std::endl;
        return ERROR( -1, err_stream.str().c_str() );
    }
    
    out.assign( base64_buf );
    std::cout << "_base64_easy_encode out: " << out << std::endl;
    return SUCCESS();
}

irods::error decode_id_token(
    std::string encoded_id_token,
    std::string* header_out,
    std::string* body_out ) {
    irods::error result = SUCCESS();

    // split encoded string into 3 parts separated by '.' header.body.signature
    std::vector<std::string> split_vector;
    boost::split( split_vector, encoded_id_token, boost::is_any_of( "." ), boost::token_compress_on );
    if ( split_vector.size() != 3 ) {
        return ERROR( -1, "ID Token did not have correct number of segments" );
    }
    std::string* p_arr[] = { header_out, body_out };

    for ( int i = 0; i < 2; i++ ) {
        std::string segment = split_vector.at(i);
        const unsigned char* in = (unsigned char*) segment.c_str();
        unsigned long decoded_len = (int)(segment.size() * (3.0/4) + 0.5);
        unsigned char decoded_buf[ decoded_len + 1 ];
        memset( decoded_buf, 0, decoded_len + 1 );

        // base64_decode requires data to be padded to 4 byte multiples
        short pad_n = segment.size() % 4;
        for ( short i = 0; i < pad_n; i++ ) {
            segment.append("=");
        }

        int decret = base64_decode( in, segment.size(), decoded_buf, &decoded_len );
        if ( decret != 0 ) {
            std::string err_msg("Base64 decoding failed on ");
            err_msg += segment;
            return ERROR( -1, err_msg );
        }

        // put the decoded buffer in the corresponding reference
        p_arr[i]->assign( (char*)decoded_buf, decoded_len );
    }
    return result;
}


// Sends auth request from client to server
irods::error openid_auth_client_request(
    irods::plugin_context& _ctx,
    rcComm_t*              _comm ) {
    std::cout << "entering openid_auth_client_request" << std::endl;
    irods::error ret;
    
    // validate incoming parameters
    if ( !_ctx.valid<irods::generic_auth_object>().ok() ) {
        return ERROR( SYS_INVALID_INPUT_PARAM, "Invalid plugin context." );
    }
    else if ( !_comm ) {
        return ERROR( SYS_INVALID_INPUT_PARAM, "null comm ptr" );
    }

    // get the auth object
    irods::generic_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::generic_auth_object>( _ctx.fco() );

    // get context string
    std::string context = ptr->context();

    // set up context string
    if ( !context.empty() ) {
        context += irods::kvp_delimiter();
    }
    context += irods::AUTH_USER_KEY + irods::kvp_association() + ptr->user_name(); 

    if ( context.size() > MAX_NAME_LEN ) {
        return ERROR( SYS_INVALID_INPUT_PARAM, "context string > max name len" );
    }

    // copy context to req in
    authPluginReqInp_t req_in;
    memset( &req_in, 0, sizeof(req_in) );
    strncpy( req_in.context_, context.c_str(), context.size() + 1 );

    // copy auth scheme to the req in 
    std::string auth_scheme = AUTH_OPENID_SCHEME;
    strncpy( req_in.auth_scheme_, auth_scheme.c_str(), auth_scheme.size() + 1 );

    // call plugin request to server in thread
    authPluginReqOut_t *req_out = 0;
    std::cout << "calling rcAuthPluginRequest" << std::endl;
    int status = rcAuthPluginRequest( _comm, &req_in, &req_out );
    
    // perform authorization handshake with server 
    // server performs authorization, waits for client to authorize via url it returns via socket
    // when client authorizes, server requests a token from OIDC provider and returns email+session token
    std::string user_name, session_token;
    std::cout << "attempting to read username and session token from server" << std::endl;
    read_from_server( &user_name, &session_token );
    std::cout << "received username: " << user_name << std::endl;
    std::cout << "received session_token: " << session_token << std::endl;
    ptr->user_name( user_name );

    // handle errors and exit
    if ( status < 0 ) {
        return ERROR( status, "call to rcAuthPluginRequest failed." );
    }
    else {
        if ( session_token.size() != 0 ) {
            // server returned a new session token, because existing one is not valid
            std::cout << "writing session_token to .irodsA" << std::endl;
            int obfret = obfSavePw( 0, 0, 1, session_token.c_str() );
            std::cout << "got " << obfret << " from obfSavePw" << std::endl;
        }
        free( req_out );
        std::cout << "leaving openid_auth_client_request" << std::endl;
        return SUCCESS();
    }
}

// Got request response from server, send response (ack) back to server
irods::error openid_auth_client_response(
    irods::plugin_context& _ctx,
    rcComm_t*              _comm ) {
    //std::cout << "entering openid_auth_client_response" << std::endl;
    irods::error result = SUCCESS();
    irods::error ret;

    // validate incoming parameters
    ret = _ctx.valid<irods::generic_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context." ) ).ok() ) {
        if ( ( result = ASSERT_ERROR( _comm, SYS_INVALID_INPUT_PARAM, "Null comm pointer." ) ).ok() ) {
            // =-=-=-=-=-=-=-
            // get the auth object
            irods::generic_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::generic_auth_object>( _ctx.fco() );

            irods::kvp_map_t kvp;
            std::string auth_scheme_key = AUTH_OPENID_SCHEME;
            kvp[irods::AUTH_SCHEME_KEY] = auth_scheme_key;
            std::string resp_str = irods::kvp_string( kvp );

            // =-=-=-=-=-=-=-
            // build the response string
            char response[ RESPONSE_LEN + 2 ];
            strncpy( response, resp_str.c_str(), RESPONSE_LEN + 2 );

            // =-=-=-=-=-=-=-
            // build the username#zonename string
            std::string user_name = ptr->user_name() + "#" + ptr->zone_name();
            char username[ MAX_NAME_LEN ];
            strncpy( username, user_name.c_str(), MAX_NAME_LEN );
            std::cout << "using user_name: " << user_name << std::endl;
            authResponseInp_t auth_response;
            auth_response.response = response;
            auth_response.username = username;
            int status = rcAuthResponse( _comm, &auth_response );
            result = ASSERT_ERROR( status >= 0, status, "Call to rcAuthResponse failed." );
        }
    }
    //std::cout << "leaving openid_auth_client_response" << std::endl;
    return result; 
}

#ifdef RODS_SERVER
static irods::error _get_server_property(std::string key, std::string& buf) {
    try {
        buf = irods::get_server_property<std::string&>(key);
    }
    catch ( const irods::exception& e) {
        return irods::error(e);
    }
    return SUCCESS();
}


irods::error openid_auth_agent_start(
    irods::plugin_context& _ctx,
    const char*            _inst_name) {
    std::cout << "entering openid_auth_agent_start" << std::endl;
    irods::error result = SUCCESS();
    irods::error ret;
    ret = _ctx.valid<irods::generic_auth_object>();
    
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context" ) ).ok() ) {
        irods::generic_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::generic_auth_object>( _ctx.fco() );
        // Reset the auth scheme here
        if ( _ctx.comm()->auth_scheme != NULL ) {
            free( _ctx.comm()->auth_scheme );
        }
        //_ctx.comm()->auth_scheme = strdup( AUTH_OPENID_SCHEME.c_str() );
        _ctx.comm()->auth_scheme = NULL;
        
    }
    std::cout << "leaving openid_auth_agent_start" << std::endl;
    return result;
}


irods::error generate_authorization_url( std::string& urlBuf ) {    
    irods::error ret;
    std::string provider_discovery_url;
    ret = _get_server_property( "openid_provider_discovery_url", provider_discovery_url );
    if ( !ret.ok() ) return ret;
    std::string client_id;
    ret = _get_server_property( "openid_client_id", client_id );
    if ( !ret.ok() ) return ret;
    std::string redirect_uri;
    ret = _get_server_property( "openid_redirect_uri", redirect_uri );
    if ( !ret.ok() ) return ret;

    std::string authorization_endpoint;
    std::string token_endpoint;

    if ( !get_provider_metadata_field( provider_discovery_url, "authorization_endpoint", authorization_endpoint )
         || !get_provider_metadata_field( provider_discovery_url, "token_endpoint", token_endpoint) ) {
        std::cout << "Provider discovery metadata missing fields" << std::endl;
        return ERROR(-1, "Provider discovery metadata missing fields");
    }

    std::string authorize_url_fmt = "%s?response_type=%s&access_type=%s&prompt=%s&scope=%s&client_id=%s&redirect_uri=%s";
    boost::format fmt( authorize_url_fmt );
    fmt % authorization_endpoint
        % "code"
        % "offline"
        % "login%20consent"
        % "openid%20profile%20email"
        % client_id
        % redirect_uri; 
        
    urlBuf = fmt.str();
    return SUCCESS();
}


irods::error openid_authorize( std::string& id_token, std::string& access_token, std::string& expires_in, std::string& refresh_token ) {
    std::cout << "entering openid_authorize" << std::endl;
    irods::error ret; 
    std::string provider_discovery_url;
    ret = _get_server_property( "openid_provider_discovery_url", provider_discovery_url );
    if ( !ret.ok() ) return ret;
    std::string client_id;
    ret = _get_server_property( "openid_client_id", client_id );
    if ( !ret.ok() ) return ret;
    std::string client_secret;
    ret = _get_server_property( "openid_client_secret", client_secret );
    if ( !ret.ok() ) return ret;
    std::string redirect_uri;
    ret = _get_server_property( "openid_redirect_uri", redirect_uri );
    if ( !ret.ok() ) return ret;
    
    std::string token_endpoint;
    std::string *request_message = accept_request( 8080 ); // TODO make configurable
    std::map<std::string,std::string> *param_map = get_params( *request_message );
    
    if ( !get_provider_metadata_field( provider_discovery_url, "token_endpoint", token_endpoint) ) {
        std::cout << "Provider discovery metadata missing fields" << std::endl;
        return ERROR(-1, "Provider discovery metadata missing fields");
    }

    // check for code in callback
    if ( param_map->find("code") != param_map->end() ) {
        std::string authorization_code = param_map->at("code");
        std::string access_token_response;
        bool token_ret = get_access_token(
                        token_endpoint,
                        authorization_code,
                        client_id,
                        client_secret,
                        redirect_uri,
                        &access_token_response);
        if ( !token_ret ) {
            return ERROR( -1, "Error retrieving access token from endpoint" );
        }
        std::cout << "Access token response: " << access_token_response << std::endl;
        std::stringstream response_stream( access_token_response );
        boost::property_tree::ptree response_tree;
        boost::property_tree::read_json( response_stream, response_tree );
        if ( response_tree.find("access_token") == response_tree.not_found()
            || response_tree.find("id_token") == response_tree.not_found()
            || response_tree.find("expires_in") == response_tree.not_found() ) {
            std::cout << "Token response missing required fields (access_token, expires_in, id_token)" << std::endl;
            return ERROR( -1, "Token response indicated an error in the request" );
        }
        else {
            id_token = response_tree.get<std::string>("id_token");
            access_token = response_tree.get<std::string>("access_token");
            expires_in = response_tree.get<std::string>("expires_in");

            if ( response_tree.find("refresh_token") == response_tree.not_found() ) {
                refresh_token = "";
                rodsLog( LOG_WARNING, "Access token response did not contain a refresh token" );
            }
            else {
                refresh_token = response_tree.get<std::string>("refresh_token");
            }

            // TODO validate
            // https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        }
    }
    else {
        return ERROR(-1, "Redirect callback missing required params");
    }
    std::cout << "leaving openid_authorize" << std::endl;
    return SUCCESS();
}

irods::error get_username_by_subject_id( rsComm_t *comm, std::string subject_id, std::string *username )
{
    rodsLog( LOG_NOTICE, "entering get_username_by_subject_id with: %s", subject_id.c_str() );
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );
    
    // select user_id
    addInxIval( &genQueryInp.selectInp, COL_USER_ID, 1 );
    addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 1 );

    // where user_dn (user auth name) = subject_id
    char condition1[MAX_NAME_LEN];
    memset( condition1, 0, MAX_NAME_LEN );
    snprintf( condition1, MAX_NAME_LEN, "='%s'", subject_id.c_str() );
    addInxVal( &genQueryInp.sqlCondInp, COL_USER_DN, condition1 );
    
    genQueryInp.maxRows = 2;
    status = rsGenQuery( comm, &genQueryInp, &genQueryOut );
    
    if ( status == CAT_NO_ROWS_FOUND || genQueryOut == NULL ) {
        std::stringstream err_stream;
        err_stream << "No results from rsGenQuery: " << status;
        rodsLog( LOG_ERROR, err_stream.str().c_str() );
        return ERROR( status, err_stream.str() );
    }
    if ( genQueryOut->rowCnt > 1 ) {
        std::stringstream err_stream;
        err_stream << "More than one user has the given subject_id: " << subject_id;
        rodsLog( LOG_ERROR, err_stream.str().c_str() );
        return ERROR( -1, err_stream.str() );
    }
    char *id = genQueryOut->sqlResult[0].value;
    char *name = genQueryOut->sqlResult[1].value;
    printf( "query by subject_id returned (id,name): (%s,%s)\n", id, name );

    username->assign( name );
    rodsLog( LOG_NOTICE, "leaving get_username_by_subject_id" );
    return SUCCESS();
}

irods::error get_username_by_session_id( rsComm_t *comm, std::string session_id, std::string *user_name )
{
    std::cout << "entering get_username_by_session_id with: " << session_id << std::endl;
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

    // select
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 1 );
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 1 );
    addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 1 );
    //addInxIval( &genQueryInp.selectInp, COL_USER_DN, 1 );

    // where meta for user matches prefix OPENID_USER_METADATA_SESSION_PREFIX
    std::string w1;
    w1 = "='";
    w1 += OPENID_USER_METADATA_SESSION_PREFIX;
    w1 += session_id;
    w1 += "'";
    std::cout << "looking for metadata key: " << w1 << std::endl;
    addInxVal( &genQueryInp.sqlCondInp, COL_META_USER_ATTR_NAME, w1.c_str() );

    // select col_user_dn* from r_meta_main, r_objt_metamap, r_user_main
    // where r_meta_main.meta_id = r_objt_metamap.meta_id AND
    // r_objt_metamap.object_id = r_user_main.user_id; 
    // join on r_objt_metamap.meta_id

    genQueryInp.maxRows = 2;

    status = rsGenQuery( comm, &genQueryInp, &genQueryOut );
    if ( status == CAT_NO_ROWS_FOUND || genQueryOut == NULL ) {
        std::stringstream err_stream;
        err_stream << "No results from rsGenQuery: " << status;
        std::cout << err_stream.str() << std::endl;
        return ERROR( status, err_stream.str() );
    }
    if ( genQueryOut->rowCnt > 1 ) {
        std::stringstream err_stream;
        err_stream << "More than one subject id found for session_id: " << session_id;
        std::cout << err_stream.str() << std::endl;
        return ERROR( -1, err_stream.str() );
    }
    char *attr_name = genQueryOut->sqlResult[0].value;
    char *attr_value = genQueryOut->sqlResult[1].value;
    char *user_buf = genQueryOut->sqlResult[2].value;
    //char *user_subject = genQueryOut->sqlResult[3].value;
    char *user_subject = user_buf;
    printf( "query by session_id returned (attribute,value,user,subject): (%s,%s,%s,%s)\n",
                attr_name, attr_value, user_buf, user_subject );
    
    user_name->assign( user_buf );
    std::cout << "returning from get_username_by_session_id" << std::endl;
    return SUCCESS();
}

irods::error get_subject_id_by_session_id( rsComm_t *comm, std::string session_id, std::string *subject_id ) {
    std::cout << "entering get_subject_id_by_session_id with: " << session_id << std::endl;
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

    // select
    //addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 0 );
    //addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 0 );
    addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 0 );
    addInxIval( &genQueryInp.selectInp, COL_USER_DN, 0 );

    // where meta for user matches prefix OPENID_USER_METADATA_SESSION_PREFIX
    std::string w1;
    w1 = "='";
    w1 += OPENID_USER_METADATA_SESSION_PREFIX;
    w1 += session_id;
    w1 += "'";
    std::cout << "looking for metadata key: " << w1 << std::endl;
    addInxVal( &genQueryInp.sqlCondInp, COL_META_USER_ATTR_NAME, w1.c_str() );
    
    // select col_user_dn* from r_meta_main, r_objt_metamap, r_user_main
    // where r_meta_main.meta_id = r_objt_metamap.meta_id AND
    // r_objt_metamap.object_id = r_user_main.user_id; 
    // join on r_objt_metamap.meta_id

    genQueryInp.maxRows = 2;

    status = rsGenQuery( comm, &genQueryInp, &genQueryOut );
    if ( status == CAT_NO_ROWS_FOUND || genQueryOut == NULL ) {
        std::stringstream err_stream;
        err_stream << "No results from rsGenQuery: " << status;
        return ERROR( status, err_stream.str() );
    }
    if ( genQueryOut->rowCnt > 1 ) {
        std::stringstream err_stream;
        err_stream << "More than one subject id found for session_id: " << session_id;
        return ERROR( -1, err_stream.str() );
    }
    char *attr_name = genQueryOut->sqlResult[0].value;
    char *attr_value = genQueryOut->sqlResult[1].value;
    char *user_name = genQueryOut->sqlResult[2].value;
    char *user_subject = genQueryOut->sqlResult[3].value;
    printf( "query by session_id returned (attribute,value,user,subject): (%s,%s,%s,%s)\n",
                attr_name, attr_value, user_name, user_subject );

    subject_id->assign( user_subject );
    std::cout << "leaving get_subject_id_by_session_id" << std::endl;
    return SUCCESS();
}


// TODO don't need refresh token here
irods::error update_session_state_after_refresh( 
                rsComm_t *comm,
                std::string session_id,
                std::string user_name,
                std::string access_token,
                std::string expiry,
                std::string refresh_token )
{
    rodsLog( LOG_NOTICE, "Updating session state with new access token (sess,user,access_token,expiry,refresh_token)" );
    irods::error ret = SUCCESS();
    // execute a metadata update operation on the user
    modAVUMetadataInp_t avu_inp;
    memset( &avu_inp, 0, sizeof( avu_inp ) );
    std::string operation("set");
    std::string obj_type("-u");
    avu_inp.arg0 = const_cast<char*>( operation.c_str() ); // operation
    avu_inp.arg1 = const_cast<char*>( obj_type.c_str() ); // obj type
    avu_inp.arg2 = const_cast<char*>( user_name.c_str() ); // username
    std::string attr_name( OPENID_USER_METADATA_SESSION_PREFIX );
    attr_name += session_id;
    avu_inp.arg3 = const_cast<char*>( attr_name.c_str() );

    // new value
    std::string val;
    irods::kvp_map_t val_map;
    val_map["access_token"] = access_token;
    val_map["expiry"] = expiry;
    //val_map["refresh_token"] = refresh_token;
    val = irods::escaped_kvp_string( val_map );
    avu_inp.arg4 = const_cast<char*>( val.c_str() );

    // ELEVATE PRIV LEVEL
    int old_auth_flag = comm->clientUser.authInfo.authFlag;
    comm->clientUser.authInfo.authFlag = LOCAL_PRIV_USER_AUTH;
    int avu_ret = rsModAVUMetadata( comm, &avu_inp );
    std::cout << "rsModAVUMetadata returned: " << avu_ret << std::endl;
    // RESET PRIV LEVEL
    comm->clientUser.authInfo.authFlag = old_auth_flag;
    if ( avu_ret < 0 ) {
        return ERROR( avu_ret, "Error updating session metadata" );
    }
    return SUCCESS();
}


irods::error set_refresh_token_for_user( rsComm_t *comm, std::string user_name, std::string refresh_token )
{
    rodsLog( LOG_NOTICE, "setting refresh token [%s] for user [%s]", refresh_token.c_str(), user_name.c_str() );
    modAVUMetadataInp_t avu_inp;
    memset( &avu_inp, 0, sizeof( avu_inp ) );

    std::string operation("set"); // use set instead of add, so only one refresh token exists per user
    std::string obj_type("-u");
    avu_inp.arg0 = (char*)operation.c_str(); // operation
    avu_inp.arg1 = (char*)obj_type.c_str(); // obj type
    avu_inp.arg2 = (char*)user_name.c_str(); // username

    //size_t prefix_len = strlen( OPENID_USER_METADATA_SESSION_PREFIX );
    size_t key_len = strlen( OPENID_USER_METADATA_REFRESH_TOKEN_KEY );
    char metadata_key[ key_len + 1 ];
    memset( metadata_key, 0, key_len + 1 );
    strncpy( metadata_key, OPENID_USER_METADATA_REFRESH_TOKEN_KEY, key_len );
    avu_inp.arg3 = metadata_key; // key

    avu_inp.arg4 = const_cast<char*>( refresh_token.c_str() );
    // ELEVATE PRIV LEVEL
    int old_auth_flag = comm->clientUser.authInfo.authFlag;
    comm->clientUser.authInfo.authFlag = LOCAL_PRIV_USER_AUTH;
    int avu_ret = rsModAVUMetadata( comm, &avu_inp );
    std::cout << "rsModAVUMetadata returned: " << avu_ret << std::endl;
    // RESET PRIV LEVEL
    comm->clientUser.authInfo.authFlag = old_auth_flag;
    
    if ( avu_ret < 0 ) {
        std::stringstream err_stream;
        err_stream << "Error setting the refresh token for user " << user_name;
        return ERROR( avu_ret, err_stream.str() );
    }
    rodsLog( LOG_NOTICE, "refresh token set successfully" );
    return SUCCESS();
}


irods::error get_refresh_token_for_user( rsComm_t *comm, std::string user_name, std::string& refresh_token )
{
    rodsLog( LOG_NOTICE, "getting refresh token for user [%s]", user_name.c_str() );
    irods::error ret = SUCCESS();
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

    // select
    //addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 0 );
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 0 );
    addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 0 );
    //addInxIval( &genQueryInp.selectInp, COL_USER_DN, 0 );

    // where meta for user attribute name matches OPENID_USER_METADATA_REFRESH_TOKEN_KEY
    std::string w1;
    w1 = "='";
    w1 += OPENID_USER_METADATA_REFRESH_TOKEN_KEY;
    w1 += "'";
    std::cout << "looking for metadata key: " << w1 << std::endl;
    addInxVal( &genQueryInp.sqlCondInp, COL_META_USER_ATTR_NAME, w1.c_str() );

    // where user matches
    std::string w2;
    w2 = "='";
    w2 += user_name;
    w2 += "'";
    addInxVal( &genQueryInp.sqlCondInp, COL_USER_NAME, w2.c_str() ); 

    // select col_user_dn* from r_meta_main, r_objt_metamap, r_user_main
    // where r_meta_main.meta_id = r_objt_metamap.meta_id AND
    // r_objt_metamap.object_id = r_user_main.user_id; 
    // join on r_objt_metamap.meta_id

    genQueryInp.maxRows = 2;

    status = rsGenQuery( comm, &genQueryInp, &genQueryOut );
    if ( status == CAT_NO_ROWS_FOUND || genQueryOut == NULL ) {
        std::stringstream err_stream;
        err_stream << "No results from rsGenQuery: " << status;
        return ERROR( status, err_stream.str() );
    }
    if ( genQueryOut->rowCnt > 1 ) {
        std::stringstream err_stream;
        err_stream << "More than one refresh token found for user: " << user_name;
        return ERROR( -1, err_stream.str() );
    }
    //char *attr_name = genQueryOut->sqlResult[0].value;
    char *attr_value = genQueryOut->sqlResult[0].value;
    char *u_name = genQueryOut->sqlResult[1].value;
    //char *user_subject = genQueryOut->sqlResult[3].value;
    printf( "query by user returned (value,user): (%s,%s)\n",
                attr_value, u_name );
    rodsLog( LOG_NOTICE, "user [%s] has refresh token [%s]\n", user_name.c_str(), attr_value );
    refresh_token.assign( attr_value );
    std::cout << "leaving get_refresh_token_for_user" << std::endl;
    return SUCCESS(); 
}


irods::error refresh_access_token( std::string& access_token, std::string& expiry, std::string& refresh_token )
{
    irods::error ret = SUCCESS();
    std::string provider_discovery_url;
    ret = _get_server_property("openid_provider_discovery_url", provider_discovery_url);
    if ( !ret.ok() ) return ret;

    std::string token_endpoint;
    if ( !get_provider_metadata_field( provider_discovery_url, "token_endpoint", token_endpoint) ) {
        return ERROR( -1, "Could not lookup token endpoint when attempting refresh" );
    }
    
    // set up the data fields which will be posted
    std::string fields;
    fields += "&refresh_token=";
    fields += refresh_token;
    fields += "&grant_type=refresh_token";
    //fields += "&access_type=offline";
    
    // set up the headers for the request
    std::string client_id;
    ret = _get_server_property( "openid_client_id", client_id );
    if ( !ret.ok() ) return ret;
    std::string client_secret;
    ret = _get_server_property( "openid_client_secret", client_secret );
    if ( !ret.ok() ) return ret;
    // clientid:clientsecret base64ed into Authorization: Basic header
    std::vector<std::string> headers;
    std::string authorization_header = "Authorization: Basic ";
    std::string creds;
    creds += client_id;
    creds += ":";
    creds += client_secret;
    std::string encoded_creds;
    _base64_easy_encode( creds, encoded_creds );
    authorization_header += encoded_creds;
    headers.push_back( authorization_header );

    std::string content_type_header = "Content-Type: application/x-www-form-urlencoded";
    headers.push_back( content_type_header );
   
    // perform curl
    std::string response;
    if ( !curl_post( token_endpoint, &fields, &headers, &response ) ) {
        return ERROR( -1, "Error sending token refresh request" );
    }

    // parse response
    std::stringstream response_stream(response);
    boost::property_tree::ptree response_tree;
    boost::property_tree::read_json(response_stream, response_tree);
    if ( response_tree.find( "access_token" ) == response_tree.not_found()
         || response_tree.find( "expires_in" ) == response_tree.not_found() ) {
        std::stringstream err_stream;
        err_stream << "Token refresh response missing required fields (access_token, expires_in):" << std::endl;
        err_stream << response << std::endl;
        return ERROR( -1, err_stream.str() );
    }
    std::string old_acc_tok( access_token );
    access_token.assign( response_tree.get<std::string>( "access_token" ) );

    // get actual expiry
    char time_buf[50];
    memset( time_buf, 0, 50 );
    getNowStr( time_buf );
    long now = atol( time_buf );
    long expires_in = std::stol( response_tree.get<std::string>( "expires_in" ), NULL, 10 );
    snprintf( time_buf, 50, "%ld", ( now + expires_in ) );
    expiry.assign( time_buf );
    
    rodsLog( LOG_NOTICE, "Successfully refreshed access token %s with (access_token, refresh_token, expiry): (%s,%s,%s)",
                            old_acc_tok.c_str(), access_token.c_str(), refresh_token.c_str(), expiry.c_str() );
    return SUCCESS();
}


/*  Need to synchronize between client and server.
    Do not return from auth_agent_request until a port is open on the server because
    when client returns from rsAuthPluginRequest, it will read from this port */
std::thread* write_thread = NULL;
std::mutex port_mutex;
std::condition_variable port_is_open_cond;
bool port_opened = false;
/**/

/*
    Uses plugin connection to connect to database. Portno is the server port that the client needs to connect to.

    msg: message to send to client first. On auth without valid session, this is the authorization url.  If empty string,
        client will interpret as their session already being valid.
    authorized: if true, will not wait for a callback request to be received. Will just send back an empty url, followed
        by the username and session id.
    session_id: if emtpy, will wait for an authorization callback to generate a session id. If not empty, will use it as the
        session id and send it back to client.
*/

void open_write_to_port( rsComm_t* comm, int portno, std::string msg, /*bool authorized,*/ std::string session_id) {
    std::unique_lock<std::mutex> lock(port_mutex);
    //std::unique_lock<std::mutex> lock(port_mutex);

    std::cout << "entering open_write_to_port with session_id: " << session_id << std::endl;
    int sockfd, conn_sockfd;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    clilen = sizeof( cli_addr );
    sockfd = socket( AF_INET, SOCK_STREAM, 0 );
    if ( sockfd < 0 ) {
        perror( "socket" );
        return;
    }
    // allow system to reuse a socket address on subsequent connection
    int opt_val = 1;
    setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&opt_val, sizeof( opt_val ) );
    memset( &serv_addr, 0, sizeof( serv_addr ) );
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons( portno );
    if ( bind( sockfd, (struct sockaddr*) &serv_addr, sizeof( serv_addr ) ) < 0 ) {
        std::stringstream err_stream("error binding to socket on port: ");
        err_stream << portno;
        perror( err_stream.str().c_str() );
        close( sockfd );
        return;
    }
    listen( sockfd, 1 );
    
    // notify that port is open so that main thread can continue and return
    std::cout << "notifying port_is_open_cond" << std::endl;
    port_opened = true;
    lock.unlock();
    port_is_open_cond.notify_all();
    
    // wait for a client connection
    conn_sockfd = accept( sockfd, (struct sockaddr*) &cli_addr, &clilen );
    if ( conn_sockfd < 0 ) {
        perror( "accept" );
        close( sockfd );
        return;
    }

    if ( session_id.empty() ) {
        std::cout << "starting write for empty session_id" << std::endl;
        int msg_len = msg.size();
        write( conn_sockfd, &msg_len, sizeof( msg_len ) );
        write( conn_sockfd, msg.c_str(), msg_len );
        std::cout << "wrote " << msg_len << " bytes for msg: " << msg << std::endl;

        // client should now browse to that url sent (msg)
        // TODO check/verify timeout on openid_authorize function
        std::string id_token_base64;
        std::string access_token;
        std::string expires_in;
        std::string refresh_token;
        
        // TODO handle error return from authorize call
        irods::error ret = openid_authorize( id_token_base64, access_token, expires_in, refresh_token );
        if ( !ret.ok() ) {
            // TODO
        }
        std::cout << "returned from authorize" << std::endl;
 
        // base64 decode the id_token to get profile info from it (name, email)
        std::string header, body;
        decode_id_token( id_token_base64, &header, &body );
        std::cout << "decoded id_token: " << body << std::endl;

        // this is too long to store as the password (session token), so create one for use in irods,
        // which will map as they key to the actual id/access token. 
        // Max irods password is 50bytes, SHA-1 is 20, base64(sha-1) is 27 bytes (28 with pad)
        char irods_session_token[MAX_PASSWORD_LEN + 1];
        memset( irods_session_token, 0, MAX_PASSWORD_LEN + 1 );
        unsigned long base64_sha1_len = (int)( 20 * 4/3 + 1);
        // include room for pad
        if ( base64_sha1_len % 4 != 0 ) {
            base64_sha1_len += 4 - ( base64_sha1_len % 4 );
        }
        // include room for null terminator
        base64_sha1_len += 1;

        char sha1_buf[ 21 ];
        memset( sha1_buf, 0, 21 );
        char base64_sha1_buf[ base64_sha1_len ];
        memset( base64_sha1_buf, 0, base64_sha1_len );

        // access_token is unique per OIDC authentication so use in in sess id
        obfMakeOneWayHash(
            HASH_TYPE_SHA1, 
            (const unsigned char*) access_token.c_str(),
            access_token.size(),
            (unsigned char*) sha1_buf );
        std::cout << "sha1 token: ";
        for ( int i = 0; i < 20; i++ ) {
            printf( "%02X", (unsigned char)sha1_buf[i] );
        }
        std::cout << std::endl;
        
        int encret = base64_encode( 
            (const unsigned char*) sha1_buf,
            20,
            (unsigned char*) base64_sha1_buf,
            &base64_sha1_len);
        std::cout << "base64_encode returned: " << encret << std::endl;
        std::cout << "base64 encoded: ";
        for ( unsigned long i = 0; i < base64_sha1_len; i++ ) {
            printf( "%c", base64_sha1_buf[i] );
        }
        std::cout << std::endl;

        strncpy( irods_session_token, base64_sha1_buf, base64_sha1_len );
        std::cout << "created session token: " << irods_session_token << std::endl;
    
        // get Subject from the id_token decoded body
        boost::property_tree::ptree body_tree;
        std::stringstream body_stream( body );
        boost::property_tree::read_json( body_stream, body_tree );
        std::string subject_id;
        if ( body_tree.find( "sub" ) == body_tree.not_found() ) {
            std::cout << "Subject ID not in the response returned by OIDC Provider" << std::endl;
            close( conn_sockfd );
            close( sockfd );
            std::cout << "leaving open_write_to_port" << std::endl;
            //return ERROR( -1, "Subject fild missing from OIDC Provider response" );
            return;
        }
        subject_id = body_tree.get<std::string>( "sub" );
        std::cout << "subject id: " << subject_id << std::endl;
    
        // put session token in the server database
        // user attribute: lib/api/include/modAVUMetadata.h
        // format: imeta add -u <username> <keyname> <value>
        
        std::string user_name;
        ret = get_username_by_subject_id( comm, subject_id, &user_name );
        if ( !ret.ok() ) {
            std::cout << "error retrieving username from subject id" << std::endl;
            return;
        }

        // plugins/database/src/db_plugin.cpp:9320 actual call
        modAVUMetadataInp_t avu_inp;
        memset( &avu_inp, 0, sizeof( avu_inp ) );
        std::string operation("add");
        std::string obj_type("-u");
        avu_inp.arg0 = (char*)operation.c_str(); // operation
        avu_inp.arg1 = (char*)obj_type.c_str(); // obj type
        avu_inp.arg2 = (char*)user_name.c_str(); // username
    
        size_t prefix_len = strlen( OPENID_USER_METADATA_SESSION_PREFIX );
        char metadata_key[ prefix_len + MAX_PASSWORD_LEN ];
        memset( metadata_key, 0, prefix_len + MAX_PASSWORD_LEN );
        strncpy( metadata_key, OPENID_USER_METADATA_SESSION_PREFIX, prefix_len );
        strncpy( metadata_key + prefix_len, irods_session_token, strlen( irods_session_token ) );
        avu_inp.arg3 = metadata_key; // key

        // in metadata entry value field, put a kvp string with access_token and expiry
        irods::kvp_map_t meta_map;
        meta_map["access_token"] = access_token;
        // set refresh token if we got one in the auth callback
        if ( refresh_token.size() > 0 ) {
            // got a new refresh token, set it in the db
            set_refresh_token_for_user( comm, user_name, refresh_token );
            //meta_map["refresh_token"] = refresh_token;
        }
        size_t time_buf_len = 50; //magic number, getNowStr limits to 16(15+null)
        char time_buf[time_buf_len];
        memset( time_buf, 0, time_buf_len );
        getNowStr( time_buf );
        // get expiration time str (now_buf + expires_in)
        long now_sec = atol( time_buf );
        long expires_in_sec = std::stol( expires_in, NULL, 10 );
        long expiry_sec = now_sec + expires_in_sec;
        memset( time_buf, 0, time_buf_len );
        snprintf( time_buf, time_buf_len, "%ld", expiry_sec );
        std::string expiry_str( time_buf );
        meta_map["expiry"] = expiry_str;
        //put into kvp string
        std::string meta_val = irods::escaped_kvp_string( meta_map );
        avu_inp.arg4 = const_cast<char*>( meta_val.c_str() ); // value
        
        // ELEVATE PRIV LEVEL
        int old_auth_flag = comm->clientUser.authInfo.authFlag;
        comm->clientUser.authInfo.authFlag = LOCAL_PRIV_USER_AUTH;
        int avu_ret = rsModAVUMetadata( comm, &avu_inp );
        std::cout << "rsModAVUMetadata returned: " << avu_ret << std::endl;
        // RESET PRIV LEVEL
        comm->clientUser.authInfo.authFlag = old_auth_flag;
    
        // write username, not subject id
        msg_len = user_name.size();
        write( conn_sockfd, &msg_len, sizeof( msg_len ) );
        write( conn_sockfd, user_name.c_str(), msg_len );
        std::cout << "wrote " << msg_len << " bytes for user_name: " << user_name << std::endl;

        // write session token 
        msg_len = base64_sha1_len; // length of token is always the same
        write( conn_sockfd, &msg_len, sizeof( msg_len ) );
        write( conn_sockfd, irods_session_token, msg_len );
        std::cout << "wrote " << msg_len << " bytes for irods_session_token: " << irods_session_token << std::endl;
    } // end !authorized
    else {
        std::cout << "starting write for existing session_id" << std::endl;

        // already authorized with a session id
        int msg_len = msg.size();
        write( conn_sockfd, &msg_len, sizeof( msg_len ) );
        write( conn_sockfd, msg.c_str(), msg_len );
        std::cout << "wrote " << msg_len << " bytes for msg: " << msg << std::endl;
        std::string subject_id, user_name;
        
        irods::error ret = get_username_by_session_id( comm, session_id, &user_name );
        // write back user_name and session token even though client should know them
        //std::string empty_msg;
        msg_len = user_name.size();
        write( conn_sockfd, &msg_len, sizeof( msg_len ) );
        write( conn_sockfd, user_name.c_str(), msg_len );
        std::cout << "wrote " << msg_len << " bytes for user_name: " << user_name << std::endl;

        msg_len = session_id.size();
        write( conn_sockfd, &msg_len, sizeof( msg_len ) );
        write( conn_sockfd, session_id.c_str(), msg_len );
        std::cout << "wrote " << msg_len << " bytes for irods_session_token: " << session_id << std::endl;
    }
    
    close( conn_sockfd );
    close( sockfd );
    std::cout << "leaving open_write_to_port" << std::endl;
    // done writing, reset thread pointer;
    delete write_thread;
    write_thread = NULL;
}


// server receives request from client 
// called from rsAuthAgentRequest, which is called by rcAuthAgentRequest
irods::error openid_auth_agent_request(
    irods::plugin_context& _ctx ) {
    std::cout << "entering openid_auth_agent_request" << std::endl;
    irods::error result = SUCCESS();
    irods::error ret;
    irods::generic_auth_object_ptr ptr;

    std::string write_msg;
    bool authorized = false;

    // validate incoming parameters
    ret = _ctx.valid<irods::generic_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context." ) ).ok() ) {
        ptr = boost::dynamic_pointer_cast<irods::generic_auth_object>( _ctx.fco() );
        if ( _ctx.comm()->auth_scheme != NULL ) {
            free( _ctx.comm()->auth_scheme );
        }
        _ctx.comm()->auth_scheme = strdup( AUTH_OPENID_SCHEME.c_str() );

        // print the context string, this should have the user/sess in it
        std::string ctx_str = ptr->context();
        std::cout << "auth_agent_request got context: " << ctx_str << std::endl;
        irods::kvp_map_t ctx_map;
        ret = irods::parse_escaped_kvp_string( ctx_str, ctx_map );
        if ( !ret.ok() ) {
            rodsLog( LOG_ERROR, "Could not parse context string sent from client: %s", ctx_str.c_str() );
            return PASS( ret );
        }
        std::string session_id = ctx_map[irods::AUTH_PASSWORD_KEY];
        std::cout << "agent request received client session: " << session_id << std::endl;
        if ( session_id.size() == 0 ) {
            // no creds sent from client
            rodsLog( LOG_NOTICE, "Client sent no session id" );
            // fall through to re-authentication code
        }
        else if ( session_id.size() != 0 ) {
            std::cout << "received a session_id from client" << std::endl;
            // got creds, verify in DB
            // using similar method to irods_client_icommands/src/imeta.cpp:473 (showUser)
            genQueryOut_t *genQueryOut;
            genQueryInp_t genQueryInp;
            memset( &genQueryInp, 0, sizeof( genQueryInp ) );

            // select
            addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 0 );
            addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 0 );
            addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_UNITS, 0 );
            addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 0 );

            // where conditions
            std::string w2;
            w2 = "='";
            w2 += OPENID_USER_METADATA_SESSION_PREFIX;
            w2 += session_id;
            w2 += "'";
            addInxVal( &genQueryInp.sqlCondInp, COL_META_USER_ATTR_NAME, w2.c_str() );

            genQueryInp.maxRows = 10;
            genQueryInp.continueInx = 0;
            genQueryInp.condInput.len = 0;

            int query_status = rsGenQuery( _ctx.comm(), &genQueryInp, &genQueryOut );
            genQueryOut_t genQueryOut2; // copy heap var to stack to simplify freeing on all the code paths
            memset( &genQueryOut2, 0, sizeof( genQueryOut2 ) );
            memcpy( &genQueryOut2, genQueryOut, sizeof( genQueryOut2 ) );
            delete genQueryOut;
            genQueryOut = &genQueryOut2;
            if ( query_status == CAT_NO_ROWS_FOUND ) {
                // this session id does not exist
                rodsLog( LOG_WARNING, "Session id [%s] not recognized, re-authenticating", session_id.c_str() );
                // fall through
                session_id = "";
                authorized = false;
            }
            else if ( genQueryOut->rowCnt > 1 ) {
                // multiple metadata entries matched this session id, not good
                return ERROR( -1, "Improper session state on server." );
            }
            else {
                // verify the return from the query
                char *metadata_value, *irods_user;
                for ( int i = 0; i < genQueryOut->rowCnt; i++ ) {
                    // attributes are: attr_name, attr_value, attr_units, user_name
                    metadata_value = strdup( genQueryOut->sqlResult[1].value );
                    irods_user = strdup( genQueryOut->sqlResult[3].value );
                }

                std::cout << "metadata_value: " << metadata_value << std::endl;
                std::cout << "irods_user: " << irods_user << std::endl;
                
                // parse metadata value, get access token+expiry
                // metadata should be formatted as kvp: 
                //   access_token=<access_token>;expiry=<expiry_timestamp>;
                irods::kvp_map_t metadata_map;
                std::string metadata_string( metadata_value );
                irods::parse_escaped_kvp_string( metadata_string, metadata_map );
                if ( metadata_map.find( "access_token" ) == metadata_map.end() 
                     || metadata_map.find( "expiry" ) == metadata_map.end() ) {
                    // maybe just fall through to re-authenticate here, instead of failing
                    return ERROR( -1, "Session state is missing required values" );
                }
                std::string access_token = metadata_map["access_token"];
                std::string expiry_str = metadata_map["expiry"];
                size_t time_buf_len = 50;
                char time_buf[ time_buf_len ];
                memset( time_buf, 0, time_buf_len );
                getNowStr( time_buf );
                long now = atol( time_buf );
                long expiry = std::stol( expiry_str, NULL, 10 );
                if ( now >= expiry ) {
                    rodsLog( LOG_NOTICE, "Access token for session %s is expired, attempting refresh", session_id.c_str() );
                    //TODO Lookup refresh token for this user
                    std::string user( irods_user );
                    std::string refresh_token;
                    ret = get_refresh_token_for_user( _ctx.comm(), user, refresh_token );

                    if ( !ret.ok() || refresh_token.size() <= 0 ) {
                        // no refresh token associated with this user in our db
                        rodsLog( LOG_NOTICE, "No refresh token associated with this session:\n%s", ret.result().c_str() );
                        
                        authorized = false;
                    }
                    else {
                        //std::string refresh_token = metadata_map["refresh_token"];
                        ret = refresh_access_token( access_token, expiry_str, refresh_token );
                        if ( !ret.ok() ) {
                            // could not obtain new access/refresh token from endpoint
                            rodsLog( LOG_WARNING, "Could not refresh token for session %s:\n%s", session_id.c_str(), ret.result().c_str() );
                            authorized = false;
                        }
                        else {
                            // update the session metadata to reflect this new access_token, expiry, and refresh_token
                            ret = update_session_state_after_refresh( _ctx.comm(), session_id, irods_user, 
                                                                      access_token, expiry_str, refresh_token );
                            if ( !ret.ok() ) {
                                rodsLog( LOG_ERROR, "Could not update session state in db after refresh" );
                                return ret;
                            }
                            else {
                                rodsLog( LOG_NOTICE, "Successfully updated session state for session %s", session_id.c_str() );
                                write_msg = "true"; // TODO make this better
                                authorized = true;
                            }
                        }
                    }
                }
                else {
                    // session is valid and not expired
                    rodsLog( LOG_NOTICE, "Session is valid" );
                    write_msg = "true";
                    authorized = true;
                }

            }
            
        } // end got a session id
        
        if ( authorized == false ) {
            rodsLog( LOG_NOTICE, "Session is not valid, generating authorization url" );
            std::string authorization_url;
            ret = generate_authorization_url( authorization_url );
            if ( !ret.ok() ) {
                return ret;
            }
            write_msg = authorization_url;
            authorized = false;
            session_id = "";
        }

        std::unique_lock<std::mutex> lock(port_mutex);
        port_opened = false;
        
        rodsLog( LOG_NOTICE, "Starting write thread" );
        write_thread = new std::thread( open_write_to_port, _ctx.comm(), OPENID_COMM_PORT, write_msg, session_id ); 
        while ( !port_opened ) {
            port_is_open_cond.wait(lock);
            std::cout << "cond woke up" << std::endl;
        }
        write_thread->detach();

    } // end context check
    
    std::cout << "leaving openid_auth_agent_request" << std::endl;
    return SUCCESS();
}


static
int check_proxy_user_privileges(
    rsComm_t *rsComm,
    int proxyUserPriv ) {
    if ( strcmp( rsComm->proxyUser.userName, rsComm->clientUser.userName )
            == 0 ) {
        return 0;
    }

    /* remote privileged user can only do things on behalf of users from
     * the same zone */
    if ( proxyUserPriv >= LOCAL_PRIV_USER_AUTH ||
            ( proxyUserPriv >= REMOTE_PRIV_USER_AUTH &&
              strcmp( rsComm->proxyUser.rodsZone, rsComm->clientUser.rodsZone ) == 0 ) ) {
        return 0;
    }
    else {
        rodsLog( LOG_ERROR,
                 "rsAuthResponse: proxyuser %s with %d no priv to auth clientUser %s",
                 rsComm->proxyUser.userName,
                 proxyUserPriv,
                 rsComm->clientUser.userName );
        return SYS_PROXYUSER_NO_PRIV;
    }
}

irods::error openid_auth_agent_response(
    irods::plugin_context& _ctx,
    authResponseInp_t* _resp ) {
    std::cout << "entering openid_auth_agent_response" << std::endl;
    // =-=-=-=-=-=-=-
    // validate incoming parameters
    if ( !_ctx.valid().ok() ) {
        return ERROR(
                   SYS_INVALID_INPUT_PARAM,
                   "invalid plugin context" );
    }
    else if ( !_resp ) {
        return ERROR(
                   SYS_INVALID_INPUT_PARAM,
                   "null authResponseInp_t ptr" );
    }

    int status;
    char *bufp;
    authCheckInp_t authCheckInp;
    rodsServerHost_t *rodsServerHost;

    char digest[RESPONSE_LEN + 2];
    char md5Buf[CHALLENGE_LEN + MAX_PASSWORD_LEN + 2];
    char serverId[MAX_PASSWORD_LEN + 2];
    MD5_CTX context;

    bufp = _rsAuthRequestGetChallenge();

    // =-=-=-=-=-=-=-
    // need to do NoLogin because it could get into inf loop for cross
    // zone auth
    status = getAndConnRcatHostNoLogin(
                 _ctx.comm(),
                 MASTER_RCAT,
                 _ctx.comm()->proxyUser.rodsZone,
                 &rodsServerHost );
    if ( status < 0 ) {
        return ERROR(
                   status,
                   "getAndConnRcatHostNoLogin failed" );
    }

    memset( &authCheckInp, 0, sizeof( authCheckInp ) );
    authCheckInp.challenge = bufp;
    authCheckInp.username = _resp->username;

    std::string resp_str = irods::AUTH_SCHEME_KEY    +
                           irods::kvp_association()  +
                           AUTH_OPENID_SCHEME +
                           irods::kvp_delimiter()    +
                           irods::AUTH_RESPONSE_KEY  +
                           irods::kvp_association()  +
                           _resp->response;
    authCheckInp.response = const_cast<char*>( resp_str.c_str() );

    authCheckOut_t *authCheckOut = NULL;
    if ( rodsServerHost->localFlag == LOCAL_HOST ) {
        status = rsAuthCheck( _ctx.comm(), &authCheckInp, &authCheckOut );
    }
    else {
        status = rcAuthCheck( rodsServerHost->conn, &authCheckInp, &authCheckOut );
        /* not likely we need this connection again */
        rcDisconnect( rodsServerHost->conn );
        rodsServerHost->conn = NULL;
    }
    if ( status < 0 || authCheckOut == NULL ) { // JMC cppcheck
        if ( authCheckOut != NULL ) {
            free( authCheckOut->serverResponse );
        }
        free( authCheckOut );
        return ERROR(
                   status,
                   "rxAuthCheck failed" );
    }

    if ( rodsServerHost->localFlag != LOCAL_HOST ) {
        if ( authCheckOut->serverResponse == NULL ) {
            rodsLog( LOG_NOTICE, "Warning, cannot authenticate remote server, no serverResponse field" );
            if ( requireServerAuth ) {
                free( authCheckOut );
                return ERROR(
                           REMOTE_SERVER_AUTH_NOT_PROVIDED,
                           "Authentication disallowed, no serverResponse field" );
            }
        }
        else {
            char *cp;
            int OK, len, i;
            if ( *authCheckOut->serverResponse == '\0' ) {
                rodsLog( LOG_NOTICE, "Warning, cannot authenticate remote server, serverResponse field is empty" );
                if ( requireServerAuth ) {
                    free( authCheckOut->serverResponse );
                    free( authCheckOut );
                    return ERROR(
                               REMOTE_SERVER_AUTH_EMPTY,
                               "Authentication disallowed, empty serverResponse" );
                }
            }
            else {
                char username2[NAME_LEN + 2];
                char userZone[NAME_LEN + 2];
                memset( md5Buf, 0, sizeof( md5Buf ) );
                strncpy( md5Buf, authCheckInp.challenge, CHALLENGE_LEN );
                parseUserName( _resp->username, username2, userZone );
                getZoneServerId( userZone, serverId );
                len = strlen( serverId );
                if ( len <= 0 ) {
                    rodsLog( LOG_NOTICE, "rsAuthResponse: Warning, cannot authenticate the remote server, no RemoteZoneSID defined in server_config.json", status );
                    if ( requireServerAuth ) {
                        free( authCheckOut->serverResponse );
                        free( authCheckOut );
                        return ERROR(
                                   REMOTE_SERVER_SID_NOT_DEFINED,
                                   "Authentication disallowed, no RemoteZoneSID defined" );
                    }
                }
                else {
                    strncpy( md5Buf + CHALLENGE_LEN, serverId, len );
                    MD5_Init( &context );
                    MD5_Update( &context, ( unsigned char* )md5Buf,
                                CHALLENGE_LEN + MAX_PASSWORD_LEN );
                    MD5_Final( ( unsigned char* )digest, &context );
                    for ( i = 0; i < RESPONSE_LEN; i++ ) {
                        if ( digest[i] == '\0' ) {
                            digest[i]++;
                        }  /* make sure 'string' doesn't
                                                              end early*/
                    }
                    cp = authCheckOut->serverResponse;
                    OK = 1;
                    for ( i = 0; i < RESPONSE_LEN; i++ ) {
                        if ( *cp++ != digest[i] ) {
                            OK = 0;
                        }
                    }
                    rodsLog( LOG_DEBUG, "serverResponse is OK/Not: %d", OK );
                    if ( OK == 0 ) {
                        free( authCheckOut->serverResponse );
                        free( authCheckOut );
                        return ERROR(
                                   REMOTE_SERVER_AUTHENTICATION_FAILURE,
                                   "Server response incorrect, authentication disallowed" );
                    }
                }
            }
        }
    }

    /* Set the clientUser zone if it is null. */
    if ( strlen( _ctx.comm()->clientUser.rodsZone ) == 0 ) {
        zoneInfo_t *tmpZoneInfo;
        status = getLocalZoneInfo( &tmpZoneInfo );
        if ( status < 0 ) {
            free( authCheckOut->serverResponse );
            free( authCheckOut );
            return ERROR(
                       status,
                       "getLocalZoneInfo failed" );
        }
        strncpy( _ctx.comm()->clientUser.rodsZone,
                 tmpZoneInfo->zoneName, NAME_LEN );
    }


    /* have to modify privLevel if the icat is a foreign icat because
     * a local user in a foreign zone is not a local user in this zone
     * and vice versa for a remote user
     */
    if ( rodsServerHost->rcatEnabled == REMOTE_ICAT ) {
        /* proxy is easy because rodsServerHost is based on proxy user */
        if ( authCheckOut->privLevel == LOCAL_PRIV_USER_AUTH ) {
            authCheckOut->privLevel = REMOTE_PRIV_USER_AUTH;
        }
        else if ( authCheckOut->privLevel == LOCAL_USER_AUTH ) {
            authCheckOut->privLevel = REMOTE_USER_AUTH;
        }

        /* adjust client user */
        if ( strcmp( _ctx.comm()->proxyUser.userName,  _ctx.comm()->clientUser.userName )
                == 0 ) {
            authCheckOut->clientPrivLevel = authCheckOut->privLevel;
        }
        else {
            zoneInfo_t *tmpZoneInfo;
            status = getLocalZoneInfo( &tmpZoneInfo );
            if ( status < 0 ) {
                free( authCheckOut->serverResponse );
                free( authCheckOut );
                return ERROR(
                           status,
                           "getLocalZoneInfo failed" );
            }

            if ( strcmp( tmpZoneInfo->zoneName,  _ctx.comm()->clientUser.rodsZone )
                    == 0 ) {
                /* client is from local zone */
                if ( authCheckOut->clientPrivLevel == REMOTE_PRIV_USER_AUTH ) {
                    authCheckOut->clientPrivLevel = LOCAL_PRIV_USER_AUTH;
                }
                else if ( authCheckOut->clientPrivLevel == REMOTE_USER_AUTH ) {
                    authCheckOut->clientPrivLevel = LOCAL_USER_AUTH;
                }
            }
            else {
                /* client is from remote zone */
                if ( authCheckOut->clientPrivLevel == LOCAL_PRIV_USER_AUTH ) {
                    authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                }
                else if ( authCheckOut->clientPrivLevel == LOCAL_USER_AUTH ) {
                    authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                }
            }
        }
    }
    else if ( strcmp( _ctx.comm()->proxyUser.userName,  _ctx.comm()->clientUser.userName )
              == 0 ) {
        authCheckOut->clientPrivLevel = authCheckOut->privLevel;
    }
    std::cout << "authCheckOut->privLevel = " << authCheckOut->privLevel << std::endl;
    std::cout << "authCheckOut->clientPrivLevel = " << authCheckOut->clientPrivLevel << std::endl;

    status = check_proxy_user_privileges( _ctx.comm(), authCheckOut->privLevel );

    if ( status < 0 ) {
        free( authCheckOut->serverResponse );
        free( authCheckOut );
        return ERROR(
                   status,
                   "check_proxy_user_privileges failed" );
    }

    rodsLog( LOG_DEBUG,
             "rsAuthResponse set proxy authFlag to %d, client authFlag to %d, user:%s proxy:%s client:%s",
             authCheckOut->privLevel,
             authCheckOut->clientPrivLevel,
             authCheckInp.username,
             _ctx.comm()->proxyUser.userName,
             _ctx.comm()->clientUser.userName );

    if ( strcmp( _ctx.comm()->proxyUser.userName,  _ctx.comm()->clientUser.userName ) != 0 ) {
        _ctx.comm()->proxyUser.authInfo.authFlag = authCheckOut->privLevel;
        _ctx.comm()->clientUser.authInfo.authFlag = authCheckOut->clientPrivLevel;
    }
    else {  /* proxyUser and clientUser are the same */
        _ctx.comm()->proxyUser.authInfo.authFlag =
            _ctx.comm()->clientUser.authInfo.authFlag = authCheckOut->privLevel;
    }

    free( authCheckOut->serverResponse );
    free( authCheckOut );
    
    std::cout << "leaving openid_auth_agent_response" << std::endl;
    return SUCCESS();

}

irods::error openid_auth_agent_verify(
    irods::plugin_context& _ctx,
    const char*            _challenge,
    const char*            _user_name,
    const char*            _response ) {
    std::cout << "entering openid_auth_agent_verify" << std::endl;

    std::cout << "leaving openid_auth_agent_verify" << std::endl;
    return SUCCESS();
}
#endif

/// @brief The openid auth plugin
class openid_auth_plugin : public irods::auth {
public:
    /// @brief Constructor
    openid_auth_plugin(
        const std::string& _name, // instance name
        const std::string& _ctx   // context
        ) : irods::auth( _name, _ctx ) { }

    /// @brief Destructor
    ~openid_auth_plugin() { }

}; // class openid_auth_plugin

/// @brief factory function to provide an instance of the plugin
extern "C"
irods::auth* plugin_factory(
    const std::string& _inst_name,
    const std::string& _context ) {
    using namespace irods;

    openid_auth_plugin* openid = new openid_auth_plugin( _inst_name, _context );
    if(!openid) {
        rodsLog(
            LOG_ERROR,
            "failed to create openid auth plugin");
        return nullptr;
    }

    openid->add_operation(
        irods::AUTH_ESTABLISH_CONTEXT,
        std::function<error(plugin_context&)>(
            openid_auth_establish_context) );
    openid->add_operation<rcComm_t*,const char*>(
        irods::AUTH_CLIENT_START,
        std::function<error(
            plugin_context&,
            rcComm_t*,
            const char*)>(openid_auth_client_start));
    openid->add_operation<rcComm_t*>(
        irods::AUTH_CLIENT_AUTH_REQUEST,
        std::function<error(plugin_context&,rcComm_t*)>(
            openid_auth_client_request ));
    openid->add_operation<rcComm_t*>(
        irods::AUTH_CLIENT_AUTH_RESPONSE,
        std::function<error(plugin_context&,rcComm_t*)>(
            openid_auth_client_response ));

#ifdef RODS_SERVER
    openid->add_operation<const char*>(
        irods::AUTH_AGENT_START,
        std::function<error(plugin_context&,const char*)>(
            openid_auth_agent_start) );
    openid->add_operation(
        irods::AUTH_AGENT_AUTH_REQUEST,
        std::function<error(plugin_context&)>(
            openid_auth_agent_request ));
    openid->add_operation<authResponseInp_t*>(
       irods::AUTH_AGENT_AUTH_RESPONSE,
       std::function<error(plugin_context&,authResponseInp_t*)>(
           openid_auth_agent_response) );
    openid->add_operation<const char*,const char*,const char*>(
       irods::AUTH_AGENT_AUTH_VERIFY,
       std::function<error(
           plugin_context&,
           const char*,
           const char*,
           const char*)>(
               openid_auth_agent_verify) );
#endif

    return openid;

} // plugin_factory


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
    std::cout << "get_provider_metadata: " << provider_metadata_url << std::endl;
    boost::property_tree::ptree *metadata_tree = new boost::property_tree::ptree();
    std::string params = "";
    std::string *metadata_string = curl_get(provider_metadata_url, &params);
    if ( metadata_string->size() == 0 ) {
        std::cout << "no metadata returned" << std::endl;
        delete metadata_tree;
        return NULL;
    }

    std::cout << "Provider metadata: " << std::endl << *metadata_string << std::endl;
    std::stringstream metadata_stream(*metadata_string);
    
    boost::property_tree::read_json(metadata_stream, *metadata_tree);
   
    const char *required_fields[] = {
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "scopes_supported",
        "response_types_supported",
        "claims_supported"};
    std::vector<std::string> metadata_required(required_fields, std::end(required_fields));
    for (std::vector<std::string>::iterator field_iter = metadata_required.begin(); field_iter != metadata_required.end(); ++field_iter)
    {
        if (metadata_tree->find(*field_iter) == metadata_tree->not_found())
        {
            std::cout << "Metadata tree missing required field: " << *field_iter << std::endl;
            delete metadata_tree;
            metadata_tree = NULL;
            break;
        }
    }
 
    delete metadata_string;
    return metadata_tree;
}


static std::map<std::string,boost::property_tree::ptree*> provider_discovery_metadata_cache;

bool get_provider_metadata_field(std::string provider_metadata_url, const std::string fieldname, std::string& value)
{
    boost::property_tree::ptree *metadata_tree;
    if ( provider_discovery_metadata_cache.find(provider_metadata_url) == provider_discovery_metadata_cache.end() ) {
        metadata_tree = get_provider_metadata(provider_metadata_url);
        if ( !metadata_tree ) {
            return false;
        }
        provider_discovery_metadata_cache.insert(std::pair<std::string,boost::property_tree::ptree*>(provider_metadata_url, metadata_tree));
    }
    else {
        metadata_tree = provider_discovery_metadata_cache.at(provider_metadata_url);
    }

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
    std::vector<std::string> split_vector;
    boost::split(split_vector, req, boost::is_any_of("\r\n"), boost::token_compress_on);
    // iterate over lines in the request string
    for (std::vector<std::string>::iterator line_iter = split_vector.begin(); line_iter != split_vector.end(); ++line_iter)
    {
        std::string line = *line_iter;
        //cout << "Request line: " << line << endl;
        if (std::regex_match(line, std::regex("GET /.*"))) { // can require path here
            std::vector<std::string> method_path_params_version_vector;
            boost::split(method_path_params_version_vector, line, boost::is_any_of(" "), boost::token_compress_on);
            if (method_path_params_version_vector.size() >= 2)
            {
                std::string path_params = method_path_params_version_vector.at(1);
                size_t param_start = path_params.find_first_of("?", 0);
                if (param_start == std::string::npos)
                {
                    std::cout << "Request had no parameters" << std::endl;
                    break;
                }
                std::string params = path_params.substr(param_start+1, std::string::npos);
                
                std::vector<std::string> param_vector;
                boost::split(param_vector, params, boost::is_any_of("&"), boost::token_compress_on);
                // iterate over parameters in the request path
                for (std::vector<std::string>::iterator param_iter = param_vector.begin(); param_iter != param_vector.end(); ++param_iter) {
                    std::string param = *param_iter;
                    std::vector<std::string> key_value_vector;
                    // split the parameter into [name, value], or [name] if no value exists
                    boost::split(key_value_vector, param, boost::is_any_of("="), boost::token_compress_on);
                    if (key_value_vector.size() == 2)
                    {
                        req_map->insert(std::pair<std::string,std::string>(key_value_vector.at(0), key_value_vector.at(1)));
                    }
                    else if (key_value_vector.size() == 1)
                    {
                        req_map->insert(std::pair<std::string,std::string>(key_value_vector.at(0), ""));
                    }
                }
            }
            else
            {
                std::cout << "GET line had " << method_path_params_version_vector.size() << " terms" << std::endl;
                // error
            }
        }
    }

    return req_map;
}

static size_t _curl_writefunction_callback( void *contents, size_t size, size_t nmemb, void *s )
{
    ((std::string*)s)->append( (char*)contents, size * nmemb );
    return size * nmemb;
}


/* Return a string response from a call to the given token endpoint url with the provided values
 */
bool get_access_token( std::string token_endpoint_url,
                               std::string authorization_code,
                               std::string client_id,
                               std::string client_secret,
                               std::string redirect_uri,
                               std::string* response)
{
    std::stringstream fields;
    fields << "code=" << authorization_code;
    fields << "&client_id=" << client_id;
    //fields << "&client_secret=" << client_secret;
    fields << "&redirect_uri=" << redirect_uri;
    fields << "&grant_type=" << "authorization_code";
    fields << "&access_type=" << "offline"; // for refresh token (not in spec, but google and globus use this)
    std::string *field_str = new std::string(fields.str());
    
    // https://tools.ietf.org/html/rfc6749#section-2.3.1
    // basic auth header with base64 encoded id:password
    std::vector<std::string> headers;

    std::string authorization_header = "Authorization: Basic ";
    std::string creds;
    creds += client_id;
    creds += ":";
    creds += client_secret;
    std::string encoded_creds;
    _base64_easy_encode( creds, encoded_creds );
    authorization_header += encoded_creds;
    headers.push_back( authorization_header );
    
    std::string content_type_header = "Content-Type: application/x-www-form-urlencoded";
    headers.push_back( content_type_header );
    
    bool ret = curl_post( token_endpoint_url, field_str, &headers, response);
    delete field_str;
    return ret;
}


bool curl_post( std::string url, std::string *fields, std::vector<std::string> *headers, std::string* response )
{
    CURL *curl;
    CURLcode res;
    curl_global_init( CURL_GLOBAL_ALL );
    curl = curl_easy_init();
    //std::string *response = new std::string();
    if ( curl )
    {
        curl_easy_setopt( curl, CURLOPT_URL, url.c_str() );
        curl_easy_setopt( curl, CURLOPT_POST, 1L );
        curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, _curl_writefunction_callback );
        curl_easy_setopt( curl, CURLOPT_WRITEDATA, response );
        std::cout << "Performing curl POST:" << url << std::endl;

        if ( fields && fields->size() > 0 ) {
            curl_easy_setopt( curl, CURLOPT_POSTFIELDSIZE, fields->length() );
            curl_easy_setopt( curl, CURLOPT_POSTFIELDS, fields->c_str() );
            std::cout << *fields << std::endl << std::endl;
        }

        if ( headers && headers->size() > 0 ) {
            struct curl_slist *curl_h = NULL;
            for ( std::vector<std::string>::iterator iter = headers->begin(); iter != headers->end(); ++iter ) {
                std::cout << "header: " << *iter << std::endl;
                curl_h = curl_slist_append( curl_h, (*iter).c_str() );
            }
            res = curl_easy_setopt( curl, CURLOPT_HTTPHEADER, curl_h );
        }

        res = curl_easy_perform( curl );
        if ( res != CURLE_OK )
        {
            fprintf( stderr, "curl_easy_perform() failed %s\n", curl_easy_strerror(res) );
            return false;
        }
        curl_easy_cleanup( curl );
    }
    curl_global_cleanup();
    return true;
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
        std::cout << "Performing curl GET: " << url << std::endl;
        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed %s\n", curl_easy_strerror(res));
            delete response;
            return NULL;
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return response;
}

std::string *accept_request(int portno)
{
    std::cout << "accepting request on port " << portno << std::endl;
    int sockfd, ret;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(portno);
    ret = bind(sockfd, (struct sockaddr *)&server_address, sizeof(server_address));
    if ( ret < 0 ) {
        std::stringstream err_stream;
        err_stream << "binding to port " << portno << " failed: ";
        perror( err_stream.str().c_str()  );
        return NULL;
    }
    listen(sockfd, 1);
    std::string *message = new std::string("");
    
    // set up connection socket
    socklen_t socksize = sizeof(client_address);
    int conn_sock_fd = accept(sockfd, (struct sockaddr *)&client_address, &socksize);
    const size_t BUF_LEN = 2048;
    char buf[BUF_LEN+1]; buf[BUF_LEN] = 0x0;
    struct timeval timeout;
    timeout.tv_sec = 5; // after accepting connection, will terminate if no data sent for 5 sec
    timeout.tv_usec = 0;
    setsockopt(conn_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    while (1)
    {
        int received_len = recv(conn_sock_fd, buf, BUF_LEN, 0);
        std::cout << "Received " << received_len << std::endl;
        if (received_len == -1)
        {
            // EAGAIN EWOULDBLOCK
            std::cout << "Timeout reached" << std::endl;
            send_success(conn_sock_fd);
            break;
        }
        if (received_len == 0)
        {
            std::cout << "Closing connection" << std::endl;
            send_success(conn_sock_fd);
            close(conn_sock_fd);
            break;
        }
        message->append(buf); 
    }
    std::cout << "accepted request: " << *message << std::endl;
    close(sockfd);
    return message;
}

