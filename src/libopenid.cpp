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
// libhttp-parser-dev (ubuntu)
// http-parser http-parser-devel (centos)
//#include <http_parser.h> //TODO maybe convert custom http parsing in accept_request to use library

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
#include <sys/un.h>
#include <netinet/in.h>
#include <curl/curl.h>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include "irods_hasher_factory.hpp"
#include "SHA256Strategy.hpp"
#include "base64.h"
#include "jansson.h"
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
static const std::string OPENID_SESSION_VALID("SUCCESS");

json_t *get_provider_metadata( std::string provider_metadata_url );

void send_success( int sockfd );
int accept_request( std::string state, std::string& code );

int get_params( std::string req, std::map<std::string,std::string>& req_map_out );

bool get_access_token( std::string token_endpoint_url,
                       std::string authorization_code,
                       std::string client_id,
                       std::string client_secret,
                       std::string redirect_uri,
                       std::string* response);

bool get_provider_metadata_field( std::string provider_metadata_url, const std::string fieldname, std::string& value );
irods::error generate_authorization_url( std::string& urlBuf, std::string auth_state, std::string auth_nonce );
/*irods::error openid_authorize(
        std::string state,
        std::string nonce,
        std::string& response_body );
*/
irods::error get_username_by_subject_id( rsComm_t *comm, std::string subject_id, std::string& username );
// OPENID helper methods
bool curl_post( std::string url, std::string *fields, std::vector<std::string> *headers, std::string *response, long *status_code );
bool curl_get( std::string url, std::string *params, std::vector<std::string> *headers, std::string *response, long *status_code );
///END DECLARATIONS

// increases output
static bool openidDebug = false;

#define OPENID_COMM_PORT 1357
#define OPENID_ACCESS_TOKEN_KEY "access_token"
#define OPENID_ID_TOKEN_KEY "id_token"
#define OPENID_EXPIRY_KEY "expiry"
#define OPENID_REFRESH_TOKEN_KEY "refresh_token"
#define OPENID_USER_METADATA_SESSION_PREFIX "openid_sess_"
#define OPENID_USER_METADATA_REFRESH_TOKEN_KEY "openid_refresh_token"

#define AUTH_FILENAME_DEFAULT ".irods/.irodsA" //under HOME

void debug( std::string msg )
{
    if ( openidDebug ) {
        puts( msg.c_str() );
    }
}

/*
    Only systems with HOME defined
*/
std::string sess_filename()
{
    char path[LONG_NAME_LEN + 1];
    memset( path, 0, LONG_NAME_LEN + 1 );
    char *env = getRodsEnvAuthFileName();
    if ( env != NULL && *env != '\0' ) {
        return std::string( env );
    }

    env = getenv( "HOME" );
    debug( "HOME: " + std::string( env ) );
    if ( env == NULL ) {
        throw std::runtime_error( "environment variable HOME not defined: "
                + std::to_string( ENVIRONMENT_VAR_HOME_NOT_DEFINED ) );
    }
    strncpy( path, env, strlen( env ) );
    strncat( path, "/", MAX_NAME_LEN - strlen( path ) );
    strncat( path, AUTH_FILENAME_DEFAULT, MAX_NAME_LEN - strlen( path ) );
    return std::string( path );
}
int write_sess_file( std::string val )
{
    debug( "entering write_sess_file" );
    FILE *fd = fopen( sess_filename().c_str(), "w+" );
    if ( !fd ) {
        perror( "could not open session file for writing" );
        return -1;
    }
    size_t n_char = fwrite( val.c_str(), sizeof( char ), val.size(), fd );
    if ( n_char != val.size() ) {
        printf( "Could not write value to session. Length was %lu but only wrote %lu\n", val.size(), n_char );
        return -2;
    }
    debug( "leaving write_sess_file" );
    return 0;
}
int read_sess_file( std::string& val_out )
{
    debug( "entering read_sess_file" );
    FILE *fd = fopen( sess_filename().c_str(), "r" );
    if ( !fd ) {
        perror( "could not open session file for reading" );
        return -1;
    }
    size_t total_bytes = 0;
    while ( true ) {
        char buf[256];
        memset( buf, 0, 256 );
        size_t n_char = fread( buf, sizeof( char ), 255, fd );
        if ( n_char > 0 ) {
            total_bytes += n_char;
            val_out.append( buf );
        }
        if ( n_char < 255 ) {
            break;
        }
    }
    if ( feof( fd ) ) {
        debug( "leaving read_sess_file: " + val_out );
        return 0;
    }
    else if ( ferror( fd ) ) {
        printf( "error during file read\n" );
        return -2;
    }
    else {
        printf( "unknown error occurred reading session file\n" );
        return -3;
    }
}


std::string json_err_message( json_error_t err )
{
    std::ostringstream stream;
    stream << "json error ";
    stream << "message: [" << err.text << "] ";
    stream << "source:[" << err.source << "] ";
    stream << "on line " << err.line << ", column " << err.column << ", byte position " << err.position;
    return stream.str();
}

/*
    Reads bytes from a socket and puts them in msg_out.

    Expects message to be formatted as byte sequences of length: [4][len]
    The first four bytes being the length of the message, followed by the message.
*/
int read_msg( int sockfd, std::string& msg_out )
{
    const int READ_LEN = 256;
    char buffer[READ_LEN + 1];
    memset( buffer, 0, READ_LEN + 1 );
    int n_bytes = 0;
    int data_len = 0;
    int total_bytes = 0;
    read( sockfd, &data_len, sizeof( data_len ) );
    memset( buffer, 0, READ_LEN );
    std::string msg;
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
        debug( "received " + std::to_string( n_bytes ) + " bytes: " + std::string( buffer ) );
        //for ( int i = 0; i < n_bytes; i++ ) {
        //    printf( "%02X", buffer[i] );
        //}
        //printf( "\n" );
        msg.append( buffer );
        total_bytes += n_bytes;
        memset( buffer, 0, READ_LEN );
    }
    msg_out = msg;
    return total_bytes;
}

/*
    Opens a socket connection to the irods_host set in ~/.irods/irods_environment.json
    on port OPENID_COMM_PORT.  Reads two messages. Messages start with 4 bytes specifying the length,
    followed immediately by the message. Bytes for the length are the raw bytes of an int, in order. (no hton/ntoh)

    The first message is the authorization url. This is printed to stdout.  The user must navigate to this url in
    order to authorize the server to communicate with the OIDC provider.

    The server will wait for the callback request from this url.  After receiving the callback, it will read the tokens
    from the request and send the email and a session token in a 2nd and 3rd message respectively.
*/
void read_from_server( int portno, std::string nonce, std::string& user_name, std::string& session_token )
{
    debug( "entering read_from_server" );
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent* server;
    //const int READ_LEN = 256;
    //char buffer[READ_LEN + 1];
    //memset( buffer, 0, READ_LEN + 1 );
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
    serv_addr.sin_port = htons( portno );
    if ( connect( sockfd, (struct sockaddr*)&serv_addr, sizeof( serv_addr ) ) < 0 ) {
        perror( "connect" );
        return;
    }
    //int data_len = 0;
    //int total_bytes = 0;

    // write nonce to server to verify that we are the same client that the auth req came from
    int msg_len = nonce.size();
    write( sockfd, &msg_len, sizeof( msg_len ) );
    write( sockfd, nonce.c_str(), msg_len );

    // read first 4 bytes (data length)
    std::string authorization_url_buf;
    if ( read_msg( sockfd, authorization_url_buf ) < 0 ) {
        perror( "error reading url from socket" );
        return;
    }
    // finished reading authorization url
    // if the auth url is "true", session is already authorized, no user action needed
    // TODO find better way to signal a valid session, debug issue with using empty message as url
    if ( authorization_url_buf.compare( OPENID_SESSION_VALID ) == 0 ) {
        std::cout << "Session is valid" << std::endl;
    }
    else {
        std::cout << "OpenID Authorization URL: \n" << authorization_url_buf << std::endl;
    }

    // wait for username message now
    if ( read_msg( sockfd, user_name ) < 0 ) {
        perror( "error reading username from server" );
        return;
    }
    debug( "read user_name: " + user_name );

    // wait for session token now
    int len = read_msg( sockfd, session_token );
    if ( len < 0 ) {
        perror( "error reading session token from server" );
        return;
    }
    debug( "read session token: " + session_token );
    debug( "session token length: " + std::to_string( len ) );

    close( sockfd );
    debug( "leaving read_from_server" );
}


irods::error openid_auth_establish_context(
    irods::plugin_context& _ctx ) {
    //debug( "entering openid_auth_establish_context" );
    irods::error result = SUCCESS();
    irods::error ret;

    ret = _ctx.valid<irods::generic_auth_object>();
    if ( !ret.ok()) {
        return ERROR(SYS_INVALID_INPUT_PARAM, "Invalid plugin context.");
    }
    irods::generic_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::generic_auth_object>( _ctx.fco() );

    //debug( "leaving openid_auth_establish_context" );
    return ret;
}

irods::error openid_auth_client_start(
    irods::plugin_context& _ctx,
    rcComm_t*              _comm,
    const char*            _context_string)
{
    debug( "entering openid_auth_client_start" );
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

            // set the provider config to use, must match a provider configured on server
            irods::kvp_map_t ctx_map;
            std::string client_provider_cfg = irods::get_environment_property<std::string&>("openid_provider");
            ctx_map["provider"] = client_provider_cfg;
            debug( "client using provider: " + ctx_map["provider"] );

            // set existing session id from pw file if exists
            std::string sess_id;
            int sess_ret = read_sess_file( sess_id );

            if ( sess_ret < 0 || sess_id.size() == 0 ) {
                std::cout << "No cached session file" << std::endl;
                debug( "obfGetPw returned: " + std::to_string( sess_ret ) );
            }
            else {
                debug( "password file contains: " + std::string( sess_id ) );
                // set the password in the context string
                ctx_map[irods::AUTH_PASSWORD_KEY] = sess_id;
            }
            debug( "client startup context" );
            for ( auto iter = ctx_map.begin(); iter != ctx_map.end(); ++iter ) {
                debug( "key: " + iter->first + ", value: " + iter->second );
            }
            debug( "" );

            std::string new_context_str = irods::escaped_kvp_string( ctx_map );
            debug( "setting context: " + new_context_str );
            ptr->context( new_context_str );
        }
    }
    debug( "leaving openid_auth_client_start" );
    return result;
}


void _sha256_hash( std::string in, char out[33] )
{
    unsigned char buf[33];
    memset( buf, 0, 33 );
    SHA256_CTX ctx;
    SHA256_Init( &ctx );
    SHA256_Update( &ctx, in.c_str(), in.size() );
    SHA256_Final( buf, &ctx );
    memcpy( out, buf, 33 );
}


irods::error _hex_from_binary( const char* in, size_t in_len, std::string& out )
{
    char buf[(2 * in_len) + 1];
    memset( buf, 0, (2 * in_len) + 1 );

    for ( size_t i = 0; i < in_len; i++ ) {
        printf( "%02x", (unsigned char) in[i] );
        sprintf( &buf[2 * i], "%02x", (unsigned char)in[i] );
    }
    debug( "_hex_from_binary returning: " + std::string( buf ) );
    out = buf;
    return SUCCESS();
}

/*
    Base64 encode a string and put it in the out reference. Handle padding and length nicely.
*/
irods::error _base64_easy_encode( const char* in, size_t in_len, std::string& out )
{
    if ( !in || in_len == 0 ) {
        return ERROR( SYS_INVALID_INPUT_PARAM, "Invalid parameters provided to base64 encode" );
    }
    unsigned long base64_len = (int)( in_len * 4/3 + 1);

    // include room for pad
    if ( base64_len % 4 != 0 ) {
        base64_len += 4 - ( base64_len % 4 );
    }
    // include room for null terminator
    base64_len += 1;

    char base64_buf[ base64_len ];
    memset( base64_buf, 0, base64_len );
    int ret = base64_encode( (const unsigned char*)in, in_len, (unsigned char*)base64_buf, &base64_len );
    if ( ret != 0 ) {
        std::stringstream err_stream;
        err_stream << "base64_encode failed with: " << ret;
        std::cout << err_stream.str() << std::endl;
        return ERROR( -1, err_stream.str().c_str() );
    }

    out.assign( base64_buf );
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
        if ( segment.size() % 4 != 0 ) {
            short pad_n = 4 - (segment.size() % 4);
            for ( short i = 0; i < pad_n; i++ ) {
                segment.append("=");
            }
        }
        int decret = base64_decode( in, segment.size(), decoded_buf, &decoded_len );
        if ( decret != 0 ) {
            std::string err_msg("Base64 decoding failed on ");
            err_msg += segment;
            std::cout << err_msg << std::endl;
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
    debug( "entering openid_auth_client_request" );
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
    debug( "calling rcAuthPluginRequest" );
    int status = rcAuthPluginRequest( _comm, &req_in, &req_out );

    irods::kvp_map_t out_map;
    irods::parse_escaped_kvp_string( req_out->result_, out_map );
    debug( "received comm info from server: port: [" + out_map["port"] + ", nonce: [" + out_map["nonce"] + "]" );
    int portno = std::stoi( out_map["port"] );
    std::string nonce = out_map["nonce"]; //

    // perform authorization handshake with server
    // server performs authorization, waits for client to authorize via url it returns via socket
    // when client authorizes, server requests a token from OIDC provider and returns email+session token
    std::string user_name, session_token;
    debug( "attempting to read username and session token from server" );
    read_from_server( portno, nonce, user_name, session_token );
    ptr->user_name( user_name );

    // handle errors and exit
    if ( status < 0 ) {
        return ERROR( status, "call to rcAuthPluginRequest failed." );
    }
    else {
        // check if session received is different from session sent
        irods::kvp_map_t context_map;
        ret = irods::parse_escaped_kvp_string( context, context_map );
        if ( !ret.ok() ) {
            rodsLog( LOG_ERROR, "Could not parse context string" );
            return ERROR( -1, "unable to parse context string after rcAuthPluginRequest" );
        }
        std::string original_sess = context_map[ irods::AUTH_PASSWORD_KEY ];
        if ( session_token.size() > NAME_LEN ) {
            throw std::runtime_error( "Session was too long: " + std::to_string( session_token.size() ) );
        }

        // copy it to the authStr field NAME_LEN=64
        strncpy( _comm->clientUser.authInfo.authStr, session_token.c_str(), session_token.size() );


        if ( session_token.size() != 0 && session_token.compare( original_sess ) != 0 ) {
            // server returned a new session token, because existing one is not valid
            //std::cout << "writing session_token to .irodsA" << std::endl;
            //int obfret = obfSavePw( 0, 0, 1, session_token.c_str() );
            // Not using obfSavePw, saving the raw hash to irodsA.
            //char fileName[MAX_PASSWORD_LEN + 10];
            //int obfret;
            //obfret = obfiGetFileName( fileName );
            //int fd = obfiOpenOutFile( fileName, 0 );
            //obfret = obfiWritePw( fd, session_token.c_str() ); 
            int a = write_sess_file( session_token );
            debug( "got " + std::to_string( a ) + " from write_sess_file" );
        }
        free( req_out );
        debug( "leaving openid_auth_client_request" );
        return SUCCESS();
    }
}

// Got request response from server, send response (ack) back to server
irods::error openid_auth_client_response(
    irods::plugin_context& _ctx,
    rcComm_t*              _comm ) {
    debug( "entering openid_auth_client_response" );
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
            // TODO if no username present, don't even bother calling rcAuthResponse because it will fail for sure
            debug( "user_name: " + user_name );
            if ( ptr->user_name().size() == 0 ) {
                return ERROR( -1, "invalid openid session, please re-run iinit" );
            }
            authResponseInp_t auth_response;
            auth_response.response = response;
            auth_response.username = username;
            int status = rcAuthResponse( _comm, &auth_response );
            result = ASSERT_ERROR( status >= 0, status, "Call to rcAuthResponse failed." );
        }
    }
    debug( "leaving openid_auth_client_response" );
    return result;
}

#ifdef RODS_SERVER
static std::string openid_provider_name;

static irods::error _get_openid_config_string( std::string key, std::string& val )
{
    try {
        const auto cfg_val = irods::get_server_property<const std::string>(
                                std::vector<std::string>{
                                irods::CFG_PLUGIN_CONFIGURATION_KW,
                                "authentication",
                                "openid",
                                key } );
        val = cfg_val;
            
    }
    catch( const irods::exception& e ) {
        return irods::error( e );
    }
    return SUCCESS();
}

static irods::error _get_provider_config( std::string key, boost::any& cfg )
{
   try {
        const auto provider_cfg = irods::get_server_property<const std::unordered_map<std::string,boost::any>>(
                            std::vector<std::string>{
                                irods::CFG_PLUGIN_CONFIGURATION_KW,
                                "authentication",
                                "openid",
                                openid_provider_name} );
        try {
            cfg = provider_cfg.at( key );
        }
        catch( const std::out_of_range& e ) {
            return ERROR( SYS_INVALID_INPUT_PARAM, "Key not found: " + key );
        }
    }
    catch ( const irods::exception& e ) {
        return irods::error( e );
    }
    return SUCCESS();
}

/*
    Looks for a server_config.json string corresponding to key, withing hte openid config section.
    Sets buf to its value.
    If the config value for key is not a string, returns an error.
*/
static irods::error _get_provider_string( std::string key, std::string& buf )
{
    boost::any cfg;
    irods::error ret = _get_provider_config( key, cfg );
    if ( !ret.ok() ) {
        return ret;
    }
    std::string value = boost::any_cast<const std::string>( cfg );
    buf = value;
    return SUCCESS();
}

/*
    Looks for an array of strings in the openid config section of the server config, with the key "scopes".
    Pushes them into the scopes_out vector.  Does not remove existing contents of scopes_out.
    If no "scopes" key found in this provider's config, returns an error.
*/
static irods::error _get_provider_scopes( std::vector<std::string>& scopes_out )
{
    boost::any cfg;
    irods::error ret = _get_provider_config( "scopes", cfg );
    if ( !ret.ok() ) {
        return ret;
    }
    const auto any_vec = boost::any_cast<const std::vector<boost::any>>( cfg );

    for ( auto it = any_vec.begin(); it != any_vec.end(); ++it ) {
        const std::string& s = boost::any_cast<const std::string&>( *it );
        std::cout << "got scope: " << s << std::endl;
        scopes_out.push_back( s );
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


/*
    Executes an 'imeta add -u <user> <key> <value>' operation.
*/
irods::error add_user_metadata( rsComm_t *comm, std::string user_name, std::string metadata_key, std::string metadata_val )
{
    // plugins/database/src/db_plugin.cpp:9320 actual call
    modAVUMetadataInp_t avu_inp;
    memset( &avu_inp, 0, sizeof( avu_inp ) );
    std::string operation("add");
    std::string obj_type("-u");
    avu_inp.arg0 = const_cast<char*>( operation.c_str() ); // operation
    avu_inp.arg1 = const_cast<char*>( obj_type.c_str() ); // obj type
    avu_inp.arg2 = const_cast<char*>( user_name.c_str() ); // username

    avu_inp.arg3 = const_cast<char*>( metadata_key.c_str() ); // key

    avu_inp.arg4 = const_cast<char*>( metadata_val.c_str() ); // value

    // ELEVATE PRIV LEVEL
    int old_auth_flag = comm->clientUser.authInfo.authFlag;
    comm->clientUser.authInfo.authFlag = LOCAL_PRIV_USER_AUTH;
    int avu_ret = rsModAVUMetadata( comm, &avu_inp );
    std::cout << "rsModAVUMetadata returned: " << avu_ret << std::endl;
    // RESET PRIV LEVEL
    comm->clientUser.authInfo.authFlag = old_auth_flag;

    if ( avu_ret < 0 ) {
        return ERROR( avu_ret, "failed to add metadata for user: " + user_name );
    }
    return SUCCESS();
}


irods::error generate_authorization_url( std::string& urlBuf, std::string auth_state, std::string auth_nonce )
{
    std::cout << "entering generate_authorization_url" << std::endl;
    irods::error ret;
    std::string provider_discovery_url;
    ret = _get_provider_string( "discovery_url", provider_discovery_url );
    if ( !ret.ok() ) return ret;
    std::string client_id;
    ret = _get_provider_string( "client_id", client_id );
    if ( !ret.ok() ) return ret;
    std::string redirect_uri;
    ret = _get_provider_string( "redirect_uri", redirect_uri );
    if ( !ret.ok() ) return ret;

    // look up the configured scopes for this provider and build a url param string with them
    std::vector<std::string> scopes;
    ret = _get_provider_scopes( scopes );
    if ( !ret.ok() ) return ret;
    // require 'openid' scope to be set in provider config. Minimum needed for auth.
    if ( std::find( scopes.begin(), scopes.end(), "openid" ) == scopes.end() ) {
        return ERROR( SYS_INVALID_INPUT_PARAM, "Client must authorize the openid scope, but this value was missing from the server's configuration for the client's configured openid provider" );
    }
    std::string scope_str;
    for ( auto it = scopes.begin(); it != scopes.end(); ++it ) {
        if ( it != scopes.begin() ) {
            scope_str += "%20";
        }
        scope_str += *it;
    }

    std::string authorization_endpoint;
    std::string token_endpoint;
    if ( !get_provider_metadata_field( provider_discovery_url, "authorization_endpoint", authorization_endpoint ) ) {
        std::cout << "Provider discovery metadata missing field: authorization_endpoint" << std::endl;
        return ERROR(-1, "Provider discovery metadata missing fields");
    }
    if ( !get_provider_metadata_field( provider_discovery_url, "token_endpoint", token_endpoint) ) {
        std::cout << "Provider discovery metadata missing field: token_endpoint" << std::endl;
        return ERROR(-1, "Provider discovery metadata missing fields");
    }


    std::ostringstream url_stream;
    url_stream << authorization_endpoint << "?";
    url_stream << "response_type=" << "code";
    url_stream << "&access_type=" << "offline";
    url_stream << "&prompt=" << "login%20consent";
    url_stream << "&scope=" << scope_str;
    url_stream << "&client_id=" << client_id;
    url_stream << "&redirect_uri=" << redirect_uri;
    url_stream << "&nonce=" << auth_nonce; // returned encoded in id_token in access_token response
    url_stream << "&state=" << auth_state; // returned in authorization redirect request

    urlBuf = url_stream.str();
    return SUCCESS();
}


/*
    Waits for a request on the configured callback port, parses the authorization code from it.
    If authorization code is present, performs a request to the token endpoint. Puts the response
    from the token endpoint in the access_token_response reference.
*/
/*
irods::error openid_authorize(
        std::string state,
        std::string nonce,
        std::string& access_token_response )
{
    std::cout << "entering openid_authorize" << std::endl;
    irods::error ret;
    std::string provider_discovery_url;
    ret = _get_provider_string( "discovery_url", provider_discovery_url );
    if ( !ret.ok() ) return ret;
    std::string client_id;
    ret = _get_provider_string( "client_id", client_id );
    if ( !ret.ok() ) return ret;
    std::string client_secret;
    ret = _get_provider_string( "client_secret", client_secret );
    if ( !ret.ok() ) return ret;
    std::string redirect_uri;
    ret = _get_provider_string( "redirect_uri", redirect_uri );
    if ( !ret.ok() ) return ret;

    std::string token_endpoint;
    std::string authorization_code;
    int retval = accept_request( state, authorization_code );
    std::cout << "returned from accept_request with authorization_code: " << authorization_code << std::endl;
    if ( retval < 0 ) {
        return ERROR( retval, "error accepting authorization request" );
    }

    if ( !get_provider_metadata_field( provider_discovery_url, "token_endpoint", token_endpoint) ) {
        std::cout << "Provider discovery metadata missing fields" << std::endl;
        return ERROR(-1, "Provider discovery metadata missing fields");
    }

    // check for code in callback
    if ( authorization_code.size() > 0 ) {
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
        return SUCCESS();
    }
    return ERROR( -1, "No authorization code in authorization callback" );
}
*/

/*
static std::string build_token_metadata(
        std::string access_token,
        std::string refresh_token,
        std::string expires_in,
        std::string scope )
{
    // in metadata entry value field, put a kvp string with access_token and expiry
    irods::kvp_map_t meta_map;
    meta_map["access_token"] = access_token;
    // set refresh token if we got one in the auth callback
    if ( refresh_token.size() > 0 ) {
        // got a new refresh token, set it in the db
        //set_refresh_token_for_user( comm, user_name, refresh_token );
        meta_map["refresh_token"] = refresh_token;
    }
    else {
        //meta_map["refresh_token"] = "";
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
    meta_map["provider"] = openid_provider_name;
    meta_map["scope"] = scope;
    //put into kvp string
    std::string meta_val = irods::escaped_kvp_string( meta_map );
    return meta_val;
}
*/


/*
irods::error handle_access_token_response(
        rsComm_t *comm,
        std::string response,
        std::string nonce, //used to verify this response
        std::string& username_out,
        std::string& session_id_out )
{
    std::cout << "entering handle_access_token_response" << std::endl;
    irods::error ret;
    json_t *root = NULL;
    json_error_t error;
    root = json_loads( response.c_str(), 0, &error );

    json_t *act_obj, *idt_obj, *exp_obj;
    act_obj = json_object_get( root, "access_token" );
    idt_obj = json_object_get( root, "id_token" );
    exp_obj = json_object_get( root, "expires_in" );

    if ( !json_is_string( act_obj ) ) {
        return ERROR( -1, "Token response missing access_token" );
    }
    std::string access_token = json_string_value( act_obj );

    if ( !json_is_string( idt_obj ) ) {
        return ERROR( -1, "Token response missing id_token" );
    }
    std::string id_token_base64 = json_string_value( idt_obj );

    std::string expires_in;
    if ( json_is_integer( exp_obj ) ) {
        expires_in = std::to_string( json_integer_value( exp_obj ) );
    }
    else if ( json_is_string( exp_obj ) ) {
        expires_in = json_string_value( exp_obj );
    }
    else {
        return ERROR( -1, "Token response missing expires_in" );
    }

    // decode id_token here instead of in caller, verify nonce field is in the id_token
    // base64 decode the id_token to get profile info from it (name, email)
    std::string header, body;
    ret = decode_id_token( id_token_base64, &header, &body );
    if ( !ret.ok() ) {
        std::cout << "failed to decode id_token" << std::endl;
        return ret;
    }
    std::cout << "decoded id_token: " << body << std::endl;

    // get Subject from the id_token decoded body
    json_error_t body_error;
    json_t *body_root = json_loads( body.c_str(), 0, &body_error );
    json_t *sub_obj = json_object_get( body_root, "sub" );
    if ( !json_is_string( sub_obj ) ) {
        std::cout << "Subject ID not in the response returned by OIDC Provider" << std::endl;
        return ERROR( -1, "subject id not in the access token response from the OIDC Provider" );
    }
    std::string subject_id = json_string_value( sub_obj );
    std::cout << "subject id: " << subject_id << std::endl;

    // verify nonce matches that sent by us on the intial authorization request
    json_t *nonce_obj = json_object_get( body_root, "nonce" );
    if ( !json_is_string( nonce_obj )
         || std::string( json_string_value( nonce_obj ) ).compare( nonce ) != 0 ) {
        // this id_token response is not from our token request
        // possible replay or man-in-the-middle attack
        rodsLog( LOG_ERROR, "Possible replay attack detected against subject [%s]", subject_id.c_str() );
        return ERROR( -1, "Token request returned invalid response" );
    }

    std::string refresh_token;
    json_t *refresh_token_obj = json_object_get( root, "refresh_token" );
    if ( !json_is_string( refresh_token_obj ) ) {
        // This doesn't break the system, is just an inconvenience
        // it means the OIDC Provider does not implement the refresh token mechanism
        refresh_token = "";
        rodsLog( LOG_WARNING, "Access token response did not contain a refresh token" );
    }
    else {
        refresh_token = json_string_value( refresh_token_obj );
    }

        // TODO validate
        // https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

    // this access_token is too long to store as the password (session token),
    // so create one for use in irods, which will map as the key to the actual
    // access_token and any additional information like expiry and per-user refresh_token
    // SHA-256 will fit within 50 bytes when base64ed (32->42(44 with pad))
    char irods_session_token[MAX_PASSWORD_LEN + 1];
    memset( irods_session_token, 0, MAX_PASSWORD_LEN + 1 );
    unsigned long base64_sha256_len = (int)( 32 * 4/3 + 1);
    // include room for pad
    if ( base64_sha256_len % 4 != 0 ) {
        base64_sha256_len += 4 - ( base64_sha256_len % 4 );
    }
    // include room for null terminator
    base64_sha256_len += 1;

    char access_token_sha256[ 33 ];
    _sha256_hash( access_token, access_token_sha256 );
    std::cout << "sha256 token: ";
    for ( int i = 0; i < 20; i++ ) {
        printf( "%02X", (unsigned char)access_token_sha256[i] );
    }
    std::cout << std::endl;

    std::string access_token_sha256_base64;
    ret = _base64_easy_encode( access_token_sha256, 32, access_token_sha256_base64 );
    if ( !ret.ok() ) {
        return ret;
    }
    std::cout << "base64 encoded: ";
    for ( unsigned long i = 0; i < access_token_sha256_base64.size(); i++ ) {
        printf( "%c", access_token_sha256_base64[i] );
    }
    std::cout << std::endl;

    if ( access_token_sha256_base64.size() > MAX_PASSWORD_LEN ) {
        std::cout << "session token was unexpectedly long: " << access_token_sha256_base64 << std::endl;
        access_token_sha256_base64.resize( MAX_PASSWORD_LEN );
    }

    //TODO issue here. When obfSavePw stores the 44byte token client-side, it results in a string longer than 50bytes.
    // temporarily truncating the session_id down to a smaller size

    // https://github.com/irods-contrib/irods_auth_plugin_openid/issues/5
    const size_t TRUNCATED_TOKEN_SIZE = 40;
    access_token_sha256_base64.resize( TRUNCATED_TOKEN_SIZE );

    strncpy( irods_session_token, access_token_sha256_base64.c_str(), access_token_sha256_base64.size() );
    std::cout << "created session token: " << irods_session_token << std::endl;

    std::string user_name;
    ret = get_username_by_subject_id( comm, subject_id, user_name );
    if ( !ret.ok() ) {
        return ERROR( -1, "error retrieving username from subject id" );
    }

    std::string metadata_key( OPENID_USER_METADATA_SESSION_PREFIX );
    metadata_key += irods_session_token;

    // put session token in the server database as user metadata
    // format: imeta add -u <username> <keyname> <value>
    std::string meta_val = build_token_metadata( access_token, refresh_token, expires_in, "openid" );
    
    // TODO new behavior
    metadata_key = OPENID_USER_METADATA_SESSION_PREFIX;

    meta_val = "subject_id=";
    meta_val += subject_id;
    meta_val += ";session_id=";
    meta_val += irods_session_token;
    ret = add_user_metadata( comm, user_name, metadata_key, meta_val );
    if ( !ret.ok() ) {
        std::cout << "error adding user metadata: " << ret.result() << std::endl;
        return ERROR( -1, "error adding user metadata" );
    }

    // set output values
    username_out = user_name;
    session_id_out = irods_session_token;
    std::cout << "leaving handle_access_token_response" << std::endl;
    return SUCCESS();
}
*/

/*
    Because Globus Auth returns separate access_tokens for authorizations for scopes that span
    resource servers (ex: auth/transfer), we need specific code to handle those.

    Globus promises that the top-level json object will always be the access_token for the 'openid' scope,
    and the array of other_tokens will always contain the access_token objects for the other scopes not
    accessible from the 'openid' one.

    All of the other_tokens metadata entries will have their key formatted:
    OPENID_USER_METADATA_SESSION_PREFIX<session_id>_<N>

    Where N is some number.  This is so it can still easily be searched for with a regex, but
    there are no duplicate metadata keys (attr_name).

    https://docs.globus.org/api/auth/reference/#authorization_code_grant_preferred
*/
/*
irods::error handle_access_token_response_globus(
        rsComm_t *comm,
        std::string response,
        std::string nonce, // used to verify this response
        std::string& username_out,
        std::string& session_id_out )
{
    std::cout << "entering handle_access_token_response_globus" << std::endl;
    irods::error ret;
    json_error_t error;
    json_t *root = json_loads( response.c_str(), 0, &error );
    bool found_id_token = false;
    std::vector<std::string> other_token_metadata;
    // Globus Auth does not strictly follow OpenID specification for access_tokens
    // store additional access tokens, associated with their scopes
    if ( openid_provider_name.compare( "globus" ) == 0 ) {
        if ( json_is_string( json_object_get( root, "id_token" ) ) ) {
            std::cout << "found id_token" << std::endl;
            ret = handle_access_token_response( comm, response, nonce, username_out, session_id_out );
            if ( !ret.ok() ) {
                return ret;
            }
            printf( "returned from standard handle_access_token_response with username: %s, session_id: %s\n",
                        username_out.c_str(), session_id_out.c_str() );
            found_id_token = true;
        }
        else {
            // expected id_token to be on the top level access_token, corresponding to openid scope and auth resource
            std::string errmsg = "Could not parse globus access token response";
            rodsLog( LOG_ERROR, errmsg.c_str() );
            return ERROR( -1, errmsg );
        }

        // loop through other_tokens if they are also in this response
        json_t *other_tokens_arr = json_object_get( root, "other_tokens" );
        if ( json_is_array( other_tokens_arr ) ) {
            // there are access_tokens for specific scopes requested in the authorization
            std::cout << "parsing other_tokens for globus token response" << std::endl;
            std::cout << "number of other_tokens: " << json_array_size( other_tokens_arr ) << std::endl;
            for ( size_t i = 0; i < json_array_size( other_tokens_arr ); i++ ) {
                json_t *token_obj = json_array_get( other_tokens_arr, i );
                if ( !json_is_object( token_obj ) ) {
                    std::cout << "error parsing other_token at index: " << i << std::endl;
                    continue;
                }
                json_t *access_token_obj = json_object_get( token_obj, "access_token" );
                json_t *expires_in_obj = json_object_get( token_obj, "expires_in" );
                json_t *refresh_token_obj = json_object_get( token_obj, "refresh_token" );
                json_t *scope_obj = json_object_get( token_obj, "scope" );
                if ( !json_is_string( access_token_obj )
                     || !json_is_integer( expires_in_obj )
                     || !json_is_string( refresh_token_obj )
                     || !json_is_string( scope_obj ) ) {
                    std::cout << "error parsing other_token due to incorrect entry type in object: " << i << std::endl;
                    continue;
                }
                std::string access_token = json_string_value( access_token_obj );
                long expires_in = json_integer_value( expires_in_obj );
                std::string refresh_token = json_string_value( refresh_token_obj );
                std::string scope = json_string_value( scope_obj );

                std::string meta_val = build_token_metadata( access_token, refresh_token, std::to_string( expires_in ), scope );
                other_token_metadata.push_back( meta_val );
            }
        }
    } // end parsed through all the tokens
    else {
        std::string errmsg = "openid_provider_name is not globus: " + openid_provider_name;
        rodsLog( LOG_NOTICE, errmsg.c_str() );
    }
    int N = 0;
    // use same metadata key as primary access_token
    std::string metadata_key( OPENID_USER_METADATA_SESSION_PREFIX );
    metadata_key += session_id_out;
    if ( found_id_token && other_token_metadata.size() > 0 ) {
        for ( auto it = other_token_metadata.begin(); it != other_token_metadata.end(); ++it ) {
            std::string indexed_meta_key = metadata_key + "_" + std::to_string( N++ );
            std::string meta_val = *it;
            std::cout << "adding user metadata: " << metadata_key << ":" << meta_val << std::endl;
            ret = add_user_metadata( comm, username_out, indexed_meta_key, meta_val );
            if ( !ret.ok() ) {
                std::string errmsg = "Error adding user metadata for globus access token response: " + ret.result();
                rodsLog( LOG_ERROR, errmsg.c_str() );
                return ERROR( -1, errmsg );
            }
        }
    }
    std::cout << "leaving handle_access_token_response_globus" << std::endl;
    return SUCCESS();
}
*/

irods::error get_subject_id_by_user_name( rsComm_t *comm, std::string user_name, std::string& subject_id )
{
    irods::error ret;
    rodsLog( LOG_NOTICE, "entering get_subject_id_by_user_name with: %s", user_name.c_str() );
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

    // select
    //addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 1 );
    //addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 1 );
    addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 1 );
    addInxIval( &genQueryInp.selectInp, COL_USER_DN, 1 );

    // where meta attr name for user matches prefix OPENID_USER_METADATA_SESSION_PREFIX
    std::string w1;
    w1 = "='";
    w1 += user_name;
    w1 += "'";
    addInxVal( &genQueryInp.sqlCondInp, COL_USER_NAME, w1.c_str() );

    genQueryInp.maxRows = 2;

    status = rsGenQuery( comm, &genQueryInp, &genQueryOut );
    if ( status == CAT_NO_ROWS_FOUND || status < 0 ) {
        std::stringstream err_stream;
        err_stream << "No results from rsGenQuery: " << status;
        std::cout << err_stream.str() << std::endl;
        freeGenQueryOut( &genQueryOut );
        return ERROR( status, err_stream.str() );
    }
    // DO NOT ALLOW MULTIPLE DN VALUES
    if ( genQueryOut->rowCnt > 1 ) {
        freeGenQueryOut( &genQueryOut );
        return ERROR( -1, "user " + user_name + "has ambiguously defined authentication names" );
    }
    char *value = genQueryOut->sqlResult[1].value;
    subject_id = value;
    freeGenQueryOut( &genQueryOut );
    
    rodsLog( LOG_NOTICE, "leaving get_subject_id_by_user_name with: %s", user_name.c_str() );
    return SUCCESS();
}

irods::error get_subject_id_by_session_id( rsComm_t *comm, std::string session_id, std::string& subject_id)
{
    irods::error ret;
    rodsLog( LOG_NOTICE, "entering get_subject_id_by_session_id with: %s", subject_id.c_str() );
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

    // select
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 1 );
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 1 );
    addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 1 );
    //addInxIval( &genQueryInp.selectInp, COL_USER_DN, 1 );

    // where meta attr name for user matches prefix OPENID_USER_METADATA_SESSION_PREFIX
    std::string w1;
    w1 = "='";
    w1 += OPENID_USER_METADATA_SESSION_PREFIX;
    w1 += "'";
    addInxVal( &genQueryInp.sqlCondInp, COL_META_USER_ATTR_NAME, w1.c_str() );
    
    std::string w2;
    w2 = " like '%";
    w2 += "session_id=";
    w2 += session_id;
    w2 += "%'";
    addInxVal( &genQueryInp.sqlCondInp, COL_META_USER_ATTR_VALUE, w2.c_str() );

    genQueryInp.maxRows = 2;

    status = rsGenQuery( comm, &genQueryInp, &genQueryOut );
    if ( status == CAT_NO_ROWS_FOUND || status < 0 ) {
        std::stringstream err_stream;
        err_stream << "No results from rsGenQuery: " << status;
        std::cout << err_stream.str() << std::endl;
        freeGenQueryOut( &genQueryOut );
        return ERROR( status, err_stream.str() );
    }
    //char *key = genQueryOut->sqlResult[0].value;
    char *value = genQueryOut->sqlResult[1].value;
    irods::kvp_map_t meta_map;
    ret = irods::parse_escaped_kvp_string( std::string( value ), meta_map );
    if ( !ret.ok() ) {
        return ret;
    }
    subject_id = meta_map["subject_id"];

    freeGenQueryOut( &genQueryOut );
    rodsLog( LOG_NOTICE, "leaving get_subject_id_by_session_id with subject_id: %s", subject_id.c_str() );
    return SUCCESS();
}

irods::error get_username_by_subject_id( rsComm_t *comm, std::string subject_id, std::string& username )
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

    if ( status == CAT_NO_ROWS_FOUND || status < 0 ) {
        std::stringstream err_stream;
        err_stream << "No results from rsGenQuery: " << status;
        rodsLog( LOG_ERROR, err_stream.str().c_str() );
        freeGenQueryOut( &genQueryOut );
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

    username = name;
    freeGenQueryOut( &genQueryOut );
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

    // where meta attr name for user matches prefix OPENID_USER_METADATA_SESSION_PREFIX
    std::string w1;
    w1 = "='";
    w1 += OPENID_USER_METADATA_SESSION_PREFIX;
    w1 += "'";
    addInxVal( &genQueryInp.sqlCondInp, COL_META_USER_ATTR_NAME, w1.c_str() );

    std::string w2;
    w2 = " like '%";
    w2 += "session_id=";
    w2 += session_id;
    w2 += "%'";
    addInxVal( &genQueryInp.sqlCondInp, COL_META_USER_ATTR_VALUE, w2.c_str() );

    genQueryInp.maxRows = 2;

    status = rsGenQuery( comm, &genQueryInp, &genQueryOut );
    if ( status == CAT_NO_ROWS_FOUND || status < 0 ) {
        std::stringstream err_stream;
        err_stream << "No results from rsGenQuery: " << status;
        std::cout << err_stream.str() << std::endl;
        freeGenQueryOut( &genQueryOut );
        return ERROR( status, err_stream.str() );
    }

    // do quick sanity check
    // TODO after removing case where metadata attr_names can be duplicated, this is no longer theoretically possible
    // make sure all of the usernames associated with this session_id are the same
    // if they are not there is something very wrong
    char *attr_name, *attr_value, *user_buf, *q_res;
    attr_name = attr_value = user_buf = q_res = NULL;

    for ( int i = 0; i < genQueryOut->rowCnt; i++ ) {
        attr_name = genQueryOut->sqlResult[0].value + ( i * genQueryOut->sqlResult[0].len );
        attr_value = genQueryOut->sqlResult[1].value + ( i * genQueryOut->sqlResult[1].len );

        q_res = genQueryOut->sqlResult[2].value + ( i * genQueryOut->sqlResult[2].len );
        if ( user_buf == NULL ) {
            user_buf = q_res;
        }
        else if ( strcmp( q_res, user_buf ) != 0 ) {
            std::string errmsg = "While looking up username by session_id, found multiple users for one session: " + session_id;
            rodsLog( LOG_ERROR, errmsg.c_str() );
            return ERROR( SYS_INVALID_INPUT_PARAM, errmsg );
        }
    }
    rodsLog( LOG_NOTICE, "query for username by session_id returned: %s", user_buf );

    user_name->assign( user_buf );
    freeGenQueryOut( &genQueryOut );
    std::cout << "returning from get_username_by_session_id" << std::endl;
    return SUCCESS();
}


/*
    Lookup the metadata id (meta_id in r_meta_main) for the openid session with session_id and scope.
    Those fields should be enought to identify a distinct entry.
*/
irods::error get_token_meta_id(
                rsComm_t *comm,
                std::string user_name,
                std::string session_id,
                std::string scope,
                std::string& meta_id )
{
    std::cout << "entering get_token_meta_id" << std::endl;
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

    // select
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_ID, 1 );
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 1 );
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 1 );
    //addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 1 );
    //addInxIval( &genQueryInp.selectInp, COL_USER_DN, 1 );

    // where meta attr name for user matches prefix OPENID_USER_METADATA_SESSION_PREFIX
    std::string w1;
    w1 = "='";
    w1 += OPENID_USER_METADATA_SESSION_PREFIX;
    w1 += session_id;
    w1 += "'";
    addInxVal( &genQueryInp.sqlCondInp, COL_META_USER_ATTR_NAME, w1.c_str() );

    std::string w2;
    w2 = "='";
    w2 += user_name;
    w2 += "'";
    addInxVal( &genQueryInp.sqlCondInp, COL_USER_NAME, w2.c_str() );

    std::string w3;
    w3 = " like '";
    w3 += "%scope=" + scope + "%'";
    addInxVal( &genQueryInp.sqlCondInp, COL_META_USER_ATTR_VALUE, w3.c_str() );

    genQueryInp.maxRows = 2;

    status = rsGenQuery( comm, &genQueryInp, &genQueryOut );
    if ( status == CAT_NO_ROWS_FOUND || status < 0 ) {
        std::stringstream err_stream;
        err_stream << "No results from rsGenQuery: " << status;
        std::cout << err_stream.str() << std::endl;
        freeGenQueryOut( &genQueryOut );
        return ERROR( status, err_stream.str() );
    }

    if ( genQueryOut->rowCnt > 1 ) {
        std::stringstream err_stream;
        err_stream << "Multiple metadata ids found for (user,sess,scope): (";
        err_stream << user_name << ",";
        err_stream << session_id << ",";
        err_stream << scope << ")";
        std::cout << err_stream.str() << std::endl;
        freeGenQueryOut( &genQueryOut );
        return ERROR( -1, err_stream.str() );
    }

    char *id = genQueryOut->sqlResult[0].value + ( 0 * genQueryOut->sqlResult[0].len );
    meta_id = id;
    freeGenQueryOut( &genQueryOut );
    std::cout << "leaving get_token_meta_id" << std::endl;
    return SUCCESS();
}


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
/*
    memset( &avu_inp, 0, sizeof( avu_inp ) );

    // delete the existing entry for this session/token combo
    std::string meta_id;
    ret = get_token_meta_id( comm, user_name, session_id, "openid", meta_id );
    if ( !ret.ok() ) {
        return ret;
    }
    std::cout << "removing metadata entry with meta_id: " << meta_id << std::endl;

    std::string operation( "rmi" );
    std::string obj_type( "-u" );
    avu_inp.arg0 = const_cast<char*>( operation.c_str() );
    avu_inp.arg1 = const_cast<char*>( obj_type.c_str() );
    avu_inp.arg2 = const_cast<char*>( user_name.c_str() );
    avu_inp.arg3 = const_cast<char*>( meta_id.c_str() );
    // note: even though imeta icommand only requires 4 args, the rsModAVUMetadata api requires 5
    // and will accept the wildcard arg as the last one. If left out it will segfault
    std::string empty( "" );
    avu_inp.arg4 = const_cast<char*>( empty.c_str() );
    avu_inp.arg5 = const_cast<char*>( empty.c_str() );
    avu_inp.arg6 = const_cast<char*>( empty.c_str() );
    avu_inp.arg7 = const_cast<char*>( empty.c_str() );
    avu_inp.arg8 = const_cast<char*>( empty.c_str() );
    avu_inp.arg9 = const_cast<char*>( empty.c_str() );

    // ELEVATE PRIV LEVEL
    int old_auth_flag = comm->clientUser.authInfo.authFlag;
    comm->clientUser.authInfo.authFlag = LOCAL_PRIV_USER_AUTH;
    int avu_ret = rsModAVUMetadata( comm, &avu_inp );
    std::cout << "rsModAVUMetadata returned: " << avu_ret << std::endl;
    // RESET PRIV LEVEL
    comm->clientUser.authInfo.authFlag = old_auth_flag;
    if ( avu_ret < 0 ) {
        return ERROR( avu_ret, "Error deleting old session metadata" );
    }
    std::cout << "successfully deleted old session metadata" << std::endl;
    */

    // add new entry for this session/token combo
    memset( &avu_inp, 0, sizeof( avu_inp ) );
    std::string operation = "set"; // use set, overrwrite any metadata entry matching this meta_attr
    std::string obj_type = "-u";
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
    val_map["refresh_token"] = refresh_token;
    val_map["scope"] = "openid";
    val_map["provider"] = openid_provider_name;
    // TODO
    // add "scope" to here, also don't destroy other entries for this session
    val = irods::escaped_kvp_string( val_map );
    avu_inp.arg4 = const_cast<char*>( val.c_str() );
    std::cout << "adding new metadata: " << attr_name << " := " << val << std::endl;
    // ELEVATE PRIV LEVEL
    int old_auth_flag = comm->clientUser.authInfo.authFlag;
    comm->clientUser.authInfo.authFlag = LOCAL_PRIV_USER_AUTH;
    int avu_ret = rsModAVUMetadata( comm, &avu_inp );
    std::cout << "rsModAVUMetadata returned: " << avu_ret << std::endl;
    // RESET PRIV LEVEL
    comm->clientUser.authInfo.authFlag = old_auth_flag;
    if ( avu_ret < 0 ) {
        return ERROR( avu_ret, "Error adding updated session metadata" );
    }
    std::cout << "leaving update_session_state_after_refresh" << std::endl;
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

/*
irods::error refresh_access_token( std::string& access_token, std::string& expiry, std::string& refresh_token )
{
    irods::error ret = SUCCESS();
    std::string provider_discovery_url;
    ret = _get_provider_string( "discovery_url", provider_discovery_url );
    if ( !ret.ok() ) return ret;

    std::string token_endpoint;
    if ( !get_provider_metadata_field( provider_discovery_url, "token_endpoint", token_endpoint ) ) {
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
    ret = _get_provider_string( "client_id", client_id );
    if ( !ret.ok() ) return ret;
    std::string client_secret;
    ret = _get_provider_string( "client_secret", client_secret );
    if ( !ret.ok() ) return ret;
    // clientid:clientsecret base64ed into Authorization: Basic header
    std::vector<std::string> headers;
    std::string authorization_header = "Authorization: Basic ";
    std::string creds;
    creds += client_id;
    creds += ":";
    creds += client_secret;
    std::string encoded_creds;
    _base64_easy_encode( creds.c_str(), creds.size(), encoded_creds );
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
    json_error_t error;
    json_t *root = json_loads( response.c_str(), 0, &error );
    json_t *access_token_obj = json_object_get( root, "access_token" );
    json_t *expires_obj = json_object_get( root, "expires_in" );

    if ( !json_is_string( access_token_obj ) ) {
        std::stringstream err_stream;
        err_stream << "Token refresh response missing access_token field" << std::endl;
        err_stream << response << std::endl;
        return ERROR( -1, err_stream.str() );
    }

    long expires_in;
    if ( json_is_integer( expires_obj ) ) {
        expires_in = json_integer_value( expires_obj );
    }
    else if ( json_is_string( expires_obj ) ) {
        // handle expires_in being returned as a string representation of an integer
        expires_in = std::stol( json_string_value( expires_obj ), NULL, 10 );
    }
    else {
        std::stringstream err_stream;
        err_stream << "Token refresh response missing expires_in field" << std::endl;
        err_stream << response << std::endl;
        return ERROR( -1, err_stream.str() );
    }

    std::string old_acc_tok( access_token );
    access_token.assign( json_string_value( access_token_obj ) );

    // get actual expiry
    char time_buf[50];
    memset( time_buf, 0, 50 );
    getNowStr( time_buf );
    long now = atol( time_buf );
    snprintf( time_buf, 50, "%ld", ( now + expires_in ) );
    expiry.assign( time_buf );

    rodsLog( LOG_NOTICE, "Successfully refreshed access token %s with (access_token, expiry): (%s,%s)",
                            old_acc_tok.c_str(), access_token.c_str(), expiry.c_str() );
    return SUCCESS();
}
*/

irods::error parse_nonce_from_authorization_url( std::string url, std::string& nonce )
{
    size_t q_idx = url.find_first_of( '?', 0 );
    if ( q_idx == std::string::npos ) {
        return ERROR( SYS_INVALID_INPUT_PARAM, "could not parse authorization url" );
    }

    std::string params = url.substr(q_idx+1, std::string::npos);
    std::map<std::string,std::string> req_map;
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
            req_map.insert(std::pair<std::string,std::string>(key_value_vector.at(0), key_value_vector.at(1)));
        }
        else if (key_value_vector.size() == 1)
        {
            req_map.insert(std::pair<std::string,std::string>(key_value_vector.at(0), ""));
        }
    }

    if ( req_map.count( "nonce" ) > 0 ) {
        nonce = req_map["nonce"];
        return SUCCESS();
    }
    else {
        return ERROR( SYS_INVALID_INPUT_PARAM, "no nonce parameter on authorization url" );
    }
}


irods::error _token_service_get(
        std::string subject_id,
        std::string provider,
        std::string scope,
        std::string nonce,
        int block,
        long *status_code,
        json_t **resp_root )
{
    irods::error ret;
    std::string url;
    ret = _get_openid_config_string( "token_service", url );
    if ( !ret.ok() ) {
        rodsLog( LOG_ERROR, "failed to look up token_service" );
        return ret;
    }
    std::string api_key;
    ret = _get_openid_config_string( "token_service_key", api_key );
    if ( !ret.ok() ) {
        rodsLog( LOG_ERROR, "failed to look up token_service_key" );
        return ret;
    }
    
    // query the token resource
    url += "/token";
    
    // add params conditionally
    std::string params;
    if ( scope.size() != 0 ) {
        params += "scope=" + scope;
    }
    else {
        return ERROR( SYS_INVALID_INPUT_PARAM, "scope cannot be empty" );
    }

    if ( provider.size() != 0 ) {
        params += "&provider=" + provider;
    }
    else {
        return ERROR( SYS_INVALID_INPUT_PARAM, "provider cannot be empty" );
    }
    
    // allow empty uid, will send us back the authorization url
    if ( subject_id.size() != 0 ) {
        params += "&uid=" + subject_id;
    }

    // wait for a specific url callback
    if ( nonce.size() != 0 ) {
        params += "&nonce=" + nonce;
    }

    // set block if desired
    if ( block != -1 ) {
        params += "&block=" + std::to_string( block );
    }

    // create headers
    std::vector<std::string> headers;
    std::string authorization_header = "Authorization: Basic ";
    authorization_header += api_key;
    headers.push_back( authorization_header );

    std::string curl_resp;
    bool curl_ret = curl_get( url, &params, &headers, &curl_resp, status_code );
    if ( !curl_ret ) {
        rodsLog( LOG_ERROR, "failed request to url %s, returned status %ld", url.c_str(), status_code );
        return ERROR( -1, "failure in curl request to token service" );
    }
    else {
        rodsLog( LOG_NOTICE, "request to token_service succeeded" );
    }
    
    json_error_t json_err;
    *resp_root = json_loads( curl_resp.c_str(), 0, &json_err );
    if ( *resp_root == NULL ) {
        rodsLog( LOG_ERROR, "json_loads returned NULL" );
        std::ostringstream msg;
        msg << "error parsing response from token service: ";
        msg << json_err_message( json_err );
        std::cout << "status code: ";
        std::cout << *status_code;
        std::cout << std::endl << "response: ";
        std::cout << curl_resp;
        //msg << std::endl << "status_code: " << *status_code;
        //msg << ", response: " << curl_resp;
        rodsLog( LOG_ERROR, msg.str().c_str() );
        return ERROR( -1, msg.str() );
    }
    std::cout << "leaving token_service_get" << std::endl;
    return SUCCESS();
}

irods::error token_service_get_url(
        std::string provider,
        std::string scope,
        long *status_code,
        json_t **resp_root )

{
    std::cout << "entering token_service_get_url" << std::endl;
    return _token_service_get( "", provider, scope, "", -1, status_code, resp_root );
}

irods::error token_service_get_by_nonce(
        std::string provider,
        std::string scope,
        std::string nonce,
        long *status_code,
        json_t **resp_root )
{
    std::cout << "entering token_service_get_by_nonce" << std::endl;
    return _token_service_get( "", provider, scope, nonce, 60, status_code, resp_root );
}

irods::error token_service_get_by_subject(
        std::string subject_id,
        std::string provider,
        std::string scope,
        int block,
        long *status_code,
        json_t **resp_root )
{
    std::cout << "entering token_service_get_by_subject" << std::endl;
    return _token_service_get( subject_id, provider, scope, "", block, status_code, resp_root );
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
    Bind to port portno and return the server socket in sock_out. If portno is 0, bind to random port and
    also update the value of portno to have that port number.

    On error return negative. On success return 0.
*/
int bind_port( int *portno, int *sock_out )
{
    int sockfd;
    struct sockaddr_in serv_addr;
    sockfd = socket( AF_INET, SOCK_STREAM, 0 );
    if ( sockfd < 0 ) {
        perror( "socket" );
        return sockfd;
    }
    int opt_val = 1;
    setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&opt_val, sizeof( opt_val ) );
    memset( &serv_addr, 0, sizeof( serv_addr ) );
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons( *portno );
    int ret;
    ret = bind( sockfd, (struct sockaddr*)&serv_addr, sizeof( serv_addr ) );
    if ( ret < 0 ) {
        std::stringstream err_stream( "error binding socket to port: " );
        err_stream << *portno;
        perror( err_stream.str().c_str() );
        close( sockfd );
        return ret;
    }
    listen( sockfd, 1 );

    // check random port assignment
    if ( *portno == 0 ) {
        socklen_t socklen = sizeof( serv_addr );
        ret = getsockname( sockfd, (struct sockaddr*)&serv_addr, &socklen );
        if ( ret < 0 ) {
            close( sockfd );
            perror( "error looking up socket for OS assigned port" );
            return ret;
        }
        int assigned_port = ntohs( serv_addr.sin_port );
        std::cout << "assigned port: " << assigned_port << std::endl;
        *portno = assigned_port;
    }
    *sock_out = sockfd;
    return 0;
}

/*
    Generate a random long. On error return negative, on success return 0.
*/
int urand( long* out )
{
    // note: seeding with time(NULL) is not unique enough if two requests are received within one second
    int fd = open( "/dev/urandom", O_RDONLY );
    if ( fd < 0 ) {
        return -1;
    }
    int rd = read( fd, out, sizeof( long ) );
    if ( rd <= 0 ) {
        return -2;
    }
    if ( rd != sizeof( long ) ) {
        return -3;
    }
    return 0;
}

/*
    Generates a random alphanumeric string of length len, and puts it in buf_out, overwriting any prior contents.
*/
int generate_nonce( size_t len, std::string& buf_out )
{
    std::string arr = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    size_t arr_len = arr.size();
    char buf[ len ];
    long r;
    for ( size_t i = 0; i < len; i++ ) {
        if ( urand( &r ) < 0 ) {
            std::cout << "failed to generate random number" << std::endl;
            return -1;
        }
        buf[ i ] = arr[ r % arr_len ];
    }
    buf_out.clear();
    buf_out.append( buf, len );
    return 0;
}

/*
    Uses plugin connection to connect to database. Portno is the server port that the client needs to connect to.

    portno: pointer to an integer. used in the call to bind_port. If value it points to is 0, will bind to OS assigned port
        and set the value of portno so caller can see the value. Otherwise, it will attempt to bind to that port number.
    nonce: will generate a nonce and set this to be that value. The client must send this to the server as the first message
        when it connects to the port. The server will check for this message and terminate the connection if not present.
    msg: message to send to client first. On auth without valid session, this is the authorization url.  If the string
        "true", client will interpret it as meaning the user does not need to re-authenticate via Identity Provider.
    session_id: if emtpy, will wait for an authorization callback to generate a session id. If not empty, will use it as the
        session id and send it back to client.
*/
void open_write_to_port(
        rsComm_t* comm,
        int *portno,
        std::string nonce,
        //std::string auth_state,
        //std::string auth_nonce,
        //std::string msg,
        std::string session_id,
        std::string user_name )
{
    std::unique_lock<std::mutex> lock(port_mutex);
    //std::unique_lock<std::mutex> lock(port_mutex);

    std::cout << "entering open_write_to_port with session_id: " << session_id << std::endl;
    irods::error ret;
    int r;
    //////////////
    int sockfd, conn_sockfd;
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    clilen = sizeof( cli_addr );

    r = bind_port( portno, &sockfd );
    if ( r < 0 ) {
        perror( "error binding to port" );
        throw std::runtime_error( "could not bind to port" );
    }
    std::cout << "bound to port: " << *portno << std::endl;
    /////////////

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

    // verify client nonce matches the nonce we sent back from auth_agent_request
    std::string client_nonce;
    if ( read_msg( conn_sockfd, client_nonce ) < 0 ) {
        perror( "error reading nonce from client" );
        return;
    }
    std::cout << "received nonce from client: " << client_nonce << std::endl;

    if ( nonce.compare( client_nonce ) != 0 ) {
        rodsLog( LOG_WARNING,
                 "Received connection on port %d from with invalid nonce. Expected [%s] but got [%s]",
                 *portno,
                 nonce.c_str(),
                 client_nonce.c_str() );
    }
    std::string msg;
    int msg_len;
    bool authorized = false;
    json_t *resp_root = NULL;
    long status_code;
    const int DONT_BLOCK = -1;
    std::string subject_id;
    
    // check if the session is valid in irods icat, ignore subject_id here
    ret = get_subject_id_by_session_id( comm, session_id, subject_id );
    if ( !ret.ok() ) {
        std::cout << "no subject id found for this session" << std::endl;
        // no matching subject, query for token with empty uid param
        subject_id = "";
        authorized = false;
    }
    else {
        authorized = true;
    }
    std::cout << "session had subject_id: " << subject_id << std::endl;

    // get the subject id to use
    ret = get_subject_id_by_user_name( comm, user_name, subject_id );
    if ( !ret.ok() ) {
        std::cout << "user had no subject id" << std::endl;
        json_decref( resp_root );
        msg = "error checking session validity";
        msg_len = msg.size();
        write( conn_sockfd, &msg_len, sizeof( msg_len ) );
        write( conn_sockfd, msg.c_str(), msg_len );
        close( conn_sockfd );
        close( sockfd );
        delete write_thread;
        write_thread = NULL;
        return;
    }
    std::cout << "user had subject_id: " << subject_id << std::endl;

    // check if the session is valid in the token service
    ret = token_service_get_by_subject( subject_id, openid_provider_name, "openid", DONT_BLOCK, &status_code, &resp_root );
    if ( !ret.ok() ) {
        std::cout << "first token_service_get failed" << std::endl;
        json_decref( resp_root );
        //return ret;
        rodsLog( LOG_ERROR, ret.result().c_str() );
        msg = "error checking session validity";
        msg_len = msg.size();
        write( conn_sockfd, &msg_len, sizeof( msg_len ) );
        write( conn_sockfd, msg.c_str(), msg_len );
        close( conn_sockfd );
        close( sockfd );
        delete write_thread;
        write_thread = NULL; 
        return;
    }
    else if ( authorized && status_code == 200 ) {
        debug( "token service returned 200" );
        // this user has an icat session and still has an active session in the token microservice (not revoked or expired)
        authorized = true;
        // send back new session_id in case the token has been updated
        std::string current_access_token;
        if ( json_is_string( json_object_get( resp_root, "access_token" ) ) ) {
            current_access_token = json_string_value( json_object_get( resp_root, "access_token" ) );
        }
        else {
            // TODO clean up
            json_decref( resp_root );
            rodsLog( LOG_ERROR, "could not parse response from token service" );
            return;
        }
        char access_token_sha256[ 33 ];
        _sha256_hash( current_access_token, access_token_sha256 );
        std::cout << "sha256 token: ";
        for ( int i = 0; i < 32; i++ ) {
            printf( "%02X", (unsigned char)access_token_sha256[i] );
        }
        std::cout << std::endl;
        _hex_from_binary( access_token_sha256, 32, session_id );

        // send back [SUCCESS, username, session id]

        // send back username
        std::string session_user;
        ret = get_username_by_session_id( comm, session_id, &session_user );
        if ( !ret.ok() ) {
            std::cout << "no user for session" << std::endl;
            authorized = false;
            session_id = "";
        }
        else if ( session_user.compare( user_name ) != 0 ) {
            std::cout << "user mismatch" << std::endl;
            // check if this session matches the session that the client is authenticating with
            authorized = false;
            msg = "could not authenticate this user with the provided session";
            msg_len = msg.size();
            write( conn_sockfd, &msg_len, sizeof( msg_len ) );
            write( conn_sockfd, msg.c_str(), msg_len );
            close( conn_sockfd );
            close( sockfd );
            delete write_thread;
            return;
        }
        else {
            authorized = true;
            rodsLog( LOG_NOTICE, "session is valid" );
            // send back SUCCESS
            msg = OPENID_SESSION_VALID;
            msg_len = msg.size();
            write( conn_sockfd, &msg_len, sizeof( msg_len ) );
            write( conn_sockfd, msg.c_str(), msg_len );

            msg_len = user_name.size();
            write( conn_sockfd, &msg_len, sizeof( msg_len ) );
            write( conn_sockfd, user_name.c_str(), msg_len );

            // send back session_id
            msg_len = session_id.size();
            write( conn_sockfd, &msg_len, sizeof( msg_len ) );
            write( conn_sockfd, session_id.c_str(), msg_len );

            rodsLog( LOG_NOTICE, "wrote (msg,user,sess) to client: (%s,%s,%s)",
                    OPENID_SESSION_VALID.c_str(),
                    user_name.c_str(),
                    session_id.c_str() );
        }
    }
    
    if ( !authorized && status_code == 200 ) {
        // no session in irods, but has already logged into the service
        msg = "SUCCESS";
    }

    if ( !authorized && status_code == 401 ) {
        // send request for a url by sending an empty uid param
        ret = token_service_get_url( openid_provider_name, "openid", &status_code, &resp_root );

        // user either wasn't provided, wasn't valid, or the session was deactivated/invalid
        // user must re-authenticate
        if ( json_is_string( json_object_get( resp_root, "authorization_url" ) ) ) {
            msg = json_string_value( json_object_get( resp_root, "authorization_url" ) );
        }
        else {
            // TODO cleanup?
            rodsLog( LOG_ERROR, "could not parse response from token service" );
            return;
        } 
    }

    if ( !authorized || status_code == 401 ) {
        std::cout << "not authorized, user must re-authenticate" << std::endl;

        // send back [url] send blocking to token service
        // if 200 send back [username, session id]
        // else send back [FAILURE, FAILURE]
        msg_len = msg.size();
        write( conn_sockfd, &msg_len, sizeof( msg_len ) );
        write( conn_sockfd, msg.c_str(), msg_len );
        
        // block against token service for 60 seconds
        json_t *block_resp_root;
        long block_status_code;
        ret = token_service_get_by_subject( subject_id, openid_provider_name, "openid", 60, &block_status_code, &block_resp_root );
        //ret = token_service_get_by_nonce( openid_provider_name, "openid", nonce, &block_status_code, &block_resp_root );
        if ( !ret.ok() ) {
            json_decref( resp_root );
            rodsLog( LOG_ERROR, ret.result().c_str() );
        }
        
        if ( block_status_code == 200 ) {
            // user logged in within 60 second limit
            json_t *token_obj = json_object_get( block_resp_root, "access_token" );
            if ( json_is_string( token_obj ) ) {
                std::string access_token = json_string_value( token_obj );
                char access_token_sha256[ 33 ];
                _sha256_hash( access_token, access_token_sha256 );
                std::cout << "sha256 token: ";
                for ( int i = 0; i < 20; i++ ) {
                    printf( "%02X", (unsigned char)access_token_sha256[i] );
                }
                std::cout << std::endl;
                _hex_from_binary( access_token_sha256, 32, session_id );

                json_decref( block_resp_root );
                // send back username
                //std::string user_name;
                //ret = get_username_by_subject_id( comm, subject_id, user_name );
                
                // write this new session to the database
                std::string metadata_key = OPENID_USER_METADATA_SESSION_PREFIX;
                std::string meta_val = "subject_id=";
                meta_val += subject_id;
                meta_val += ";session_id=";
                meta_val += session_id;
                ret = add_user_metadata( comm, user_name, metadata_key, meta_val );
                // TODO handle return

                // send back the user name
                msg_len = user_name.size();
                write( conn_sockfd, &msg_len, sizeof( msg_len ) );
                write( conn_sockfd, user_name.c_str(), msg_len );

                // send back the session id
                msg_len = session_id.size();
                write( conn_sockfd, &msg_len, sizeof( msg_len ) );
                write( conn_sockfd, session_id.c_str(), msg_len );
                
                rodsLog( LOG_NOTICE, "wrote (msg,user,sess) to client: (%s,%s,%s)",
                        msg.c_str(),
                        user_name.c_str(),
                        session_id.c_str() );
            }
            else {
                rodsLog( LOG_ERROR, "could not parse response from token service on blocking request" );
                // TODO cleanly cut connection with client
            }
        }
        else {
            rodsLog( LOG_ERROR, "token service returned status [%ld] on blocking token request", block_status_code );
            // failed to log in TODO
        }
    }
    else {
        rodsLog( LOG_ERROR, "token service returned status [%ld] on non-blocking token request", status_code );
    }
    
    // free json from first call to token service
    json_decref( resp_root );

    // close client connection
    close( conn_sockfd );

    // close server socket
    close( sockfd );
    std::cout << "leaving open_write_to_port" << std::endl;
    // done writing, reset thread pointer; // looks like agents are fresh processes, so this can be changed
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
        std::string user_name = ctx_map[irods::AUTH_USER_KEY];
        // set global field to the value the client requested
        openid_provider_name = ctx_map["provider"];
        std::cout << "agent request received client session: " << session_id << std::endl;

        /*
            nonce:
                send back to plugin client.
                used to verify that a connection on secondary comm port is actually that client
        */
        std::string nonce;
        // this is sent as part of irods rpc, careful about size TODO check for constraints on this size
        int nonce_ret = generate_nonce( 16, nonce );
        if ( nonce_ret < 0 ) {
            return ERROR( nonce_ret, "error generating nonce" );
        }
        std::cout << "generated nonce: " << nonce << std::endl;

        int portno = 0;
        std::unique_lock<std::mutex> lock(port_mutex);
        port_opened = false;
        rodsLog( LOG_NOTICE, "Starting write thread" );
        write_thread = new std::thread(
                            open_write_to_port,
                            _ctx.comm(),
                            &portno,
                            nonce,
                            session_id,
                            user_name);
        while ( !port_opened ) {
            port_is_open_cond.wait(lock);
            std::cout << "cond woke up" << std::endl;
        }
        std::cout << "main thread received portno: " << portno << std::endl;
        irods::kvp_map_t return_map;
        std::string port_str = std::to_string( portno );
        return_map["port"] = port_str;
        return_map["nonce"] = nonce; // client plugin must send this as first message when connecting to port
        ptr->request_result( irods::escaped_kvp_string( return_map ) );
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
    std::cout << "proxyUser.authInfo.authFlag = " << _ctx.comm()->proxyUser.authInfo.authFlag << std::endl;
    std::cout << "clientUser.authInfo.authFlag = " << _ctx.comm()->clientUser.authInfo.authFlag << std::endl;
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
    //std::cout << "entering openid_auth_agent_verify" << std::endl;

    //std::cout << "leaving openid_auth_agent_verify" << std::endl;
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
 * send a GET request for that document and put it in a json_t object from jansson library.
 */
// TODO agents are separate processes, could use shared memory, or not care about having to look up the metadata each time
static std::map<std::string,std::string> provider_discovery_metadata_cache;
json_t *get_provider_metadata( std::string url )
{
    std::cout << "get_provider_metadata: " << url << std::endl;

    json_t *root;
    json_error_t error;
    std::string metadata_string;

    if ( provider_discovery_metadata_cache.find( url ) == provider_discovery_metadata_cache.end() ) {
        std::string params = "";
        std::string curl_resp;
        long status_code;
        bool curl_ret = curl_get( url, &params, NULL, &curl_resp, &status_code );
        if ( !curl_ret || curl_resp.size() == 0 ) {
            std::cout << "no metadata returned" << std::endl;
            return NULL;
        }
        metadata_string = curl_resp;
        provider_discovery_metadata_cache.insert( std::pair<std::string,std::string>( url, curl_resp ) );
    }
    else {
        metadata_string = provider_discovery_metadata_cache.at( url );
    }

    root = json_loads( metadata_string.c_str(), 0, &error );
    if ( !root ) {
        rodsLog( LOG_ERROR, "Could not parse provider metadata response" );
        // TODO look at error struct
        return NULL;
    }

    char *dumps = json_dumps( root, JSON_INDENT(2) );
    std::cout << "Provider metadata: " << std::endl << dumps << std::endl;
    free( dumps );

    const char *required_fields[] = {
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "scopes_supported",
        "response_types_supported",
        "claims_supported"};
    std::vector<std::string> metadata_required(required_fields, std::end(required_fields));

    for ( auto it = metadata_required.begin(); it != metadata_required.end(); ++it ) {
        json_t *obj = json_object_get( root, (*it).c_str() );
        if ( !obj ) {
            rodsLog( LOG_ERROR, "Provider metadata missing required field: %s", (*it).c_str() );
            json_decref( root );
            return NULL;
        }
    }

    return root;
}

/*
    Currently only works on discovery metadata fields of string type
*/
bool get_provider_metadata_field(std::string provider_metadata_url, const std::string fieldname, std::string& value)
{
    std::cout << "entering get_provider_metadata_field with fieldname: " << fieldname << std::endl;
    json_t *root = NULL;
    root = get_provider_metadata( provider_metadata_url );
    if ( !root ) {
        std::cout << "couldn't get metadata" << std::endl;
    }
    json_t *obj = json_object_get( root, fieldname.c_str() );
    if ( !obj ) {
        std::cout << "json_object_get returned null for " << fieldname << std::endl;
    }

    if ( json_is_string( obj ) ) {
        value = json_string_value( obj );
        json_decref( root );
        return true;
    }
    else {
        std::cout << "json object is not a string" << std::endl;
        json_decref( root );
        return false;
    }
}


/* Takes a GET request string. This is the literal string representation of the request.
 * Looks for the line with the request path, and splits it up into pair<key, value> for each request parameter
 * If the key has no value, the value part of the pair is left as an empty string.
 * Returns a map<string,string> of each request parameter
 */
int get_params(std::string req, std::map<std::string,std::string>& req_map_out)
{
    std::map<std::string,std::string> *req_map = &req_map_out;
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

    return 0;
}

static size_t _curl_writefunction_callback( void *contents, size_t size, size_t nmemb, void *s )
{
    ((std::string*)s)->append( (char*)contents, size * nmemb );
    return size * nmemb;
}


/* Return a string response from a call to the given token endpoint url with the provided values
 */
/*bool get_access_token( std::string token_endpoint_url,
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
    _base64_easy_encode( creds.c_str(), creds.size(), encoded_creds );
    authorization_header += encoded_creds;
    headers.push_back( authorization_header );

    std::string content_type_header = "Content-Type: application/x-www-form-urlencoded";
    headers.push_back( content_type_header );

    bool ret = curl_post( token_endpoint_url, field_str, &headers, response);
    delete field_str;
    return ret;
}*/


bool curl_post( std::string url, std::string *fields, std::vector<std::string> *headers, std::string *response, long *status_code )
{
    CURL *curl;
    CURLcode res;
    curl_global_init( CURL_GLOBAL_ALL );
    curl = curl_easy_init();
    if ( curl ) {
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
        if ( res != CURLE_OK ) {
            fprintf( stderr, "curl_easy_perform() failed %s\n", curl_easy_strerror(res) );
            return false;
        }
        curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, status_code );
        curl_easy_cleanup( curl );
    }
    curl_global_cleanup();
    return true;
}

bool curl_get( std::string url, std::string *params, std::vector<std::string> *headers, std::string *response, long *status_code )
{
    CURL *curl;
    CURLcode res;
    curl_global_init( CURL_GLOBAL_ALL );
    curl = curl_easy_init();
    if ( curl ) {
        curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, _curl_writefunction_callback);
        curl_easy_setopt( curl, CURLOPT_WRITEDATA, response );

        if ( params && params->size() > 0 ) {
            std::cout << "params: " << *params << std::endl;
            url += "?" + *params;
        }
        std::cout << "Performing curl GET: " << url << std::endl;
        curl_easy_setopt( curl, CURLOPT_URL, url.c_str() );
        
        if ( headers && headers->size() > 0 ) {
            struct curl_slist *curl_h = NULL;
            for ( auto iter = headers->begin(); iter != headers->end(); ++iter ) {
                std::cout << "header: " << *iter << std::endl;
                curl_h = curl_slist_append( curl_h, (*iter).c_str() );
            }
            res = curl_easy_setopt( curl, CURLOPT_HTTPHEADER, curl_h );
        }
        // set verbose mode
        res = curl_easy_setopt( curl, CURLOPT_VERBOSE, 1 );        

        // TODO temporarily disable SSL peer verification
        res = curl_easy_setopt( curl, CURLOPT_SSL_VERIFYPEER, 0 );
        res = curl_easy_perform( curl );
        if (res != CURLE_OK ) {
            fprintf( stderr, "curl_easy_perform() failed %s\n", curl_easy_strerror(res) );
            return false;
        }
        curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, status_code );
        curl_easy_cleanup( curl );
    }
    curl_global_cleanup();
    return true;
}

/*
static std::atomic_bool keep_accepting_requests( true );
void redirect_server_accept_thread( int request_port, std::map<std::string,int> *listeners )
{
    rodsLog( LOG_NOTICE, "starting redirect accept thread on port %d", request_port );
    int request_queue_len = 20;
    int sockfd, ret;
    struct sockaddr_in server_address;
    //struct sockaddr_in client_address;
    sockfd = socket( AF_INET, SOCK_STREAM, 0 );

    memset( &server_address, 0, sizeof( server_address ) );
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl( INADDR_ANY );
    server_address.sin_port = htons( request_port );
    ret = bind( sockfd, (struct sockaddr *)&server_address, sizeof(server_address) );
    if ( ret < 0 ) {
        std::stringstream err_stream;
        err_stream << "binding to port " << request_port << " failed: ";
        perror( err_stream.str().c_str()  );
        return;
    }
    listen( sockfd, request_queue_len );
    rodsLog( LOG_NOTICE, "redirect server accepting requests on port %d", request_port );
    const long tv_accept_sec = 30;
    const long tv_recv_sec = 5;
    const size_t BUF_LEN = 2048;
    socklen_t socksize = sizeof( sockaddr_in );
    while ( keep_accepting_requests ) {
        // accept new requests
        // set up connection socket
        struct sockaddr_in client_address;
        // maybe don't timeout the accept, possible race condition on connection during small reset window
        struct timeval timeout_accept;
        timeout_accept.tv_sec = tv_accept_sec;
        timeout_accept.tv_usec = 0;
        fd_set read_fds;
        FD_ZERO( &read_fds );
        FD_SET( sockfd, &read_fds );
        ret = select( sockfd+1, &read_fds, NULL, NULL, &timeout_accept ); // wait for connection for 30 sec
        if ( ret < 0 ) {
            perror( "error setting timeout with select" );
            return;
        }
        else if ( ret == 0 ) {
            rodsLog( LOG_NOTICE, "Timeout reached after %d sec while accepting request on port %d", timeout_accept.tv_sec, request_port );
            continue; // this is just so the thread will check to see if it should stop every tv_sec
        }

        int conn_sock_fd = accept(sockfd, (struct sockaddr *)&client_address, &socksize);
        rodsLog( LOG_NOTICE, "accepted request on port %d", request_port );

        char buf[BUF_LEN+1]; buf[BUF_LEN] = 0x0;
        struct timeval timeout_recv;
        timeout_recv.tv_sec = tv_recv_sec; // after accepting connection, will terminate if no data sent for 5 sec
        timeout_recv.tv_usec = 0;
        setsockopt( conn_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout_recv, sizeof(timeout_recv) );
        std::string request_str;
        while (1) {
            int received_len = recv( conn_sock_fd, buf, BUF_LEN, 0 );
            std::cout << "Received " << received_len << std::endl;
            if (received_len == -1) {
                // EAGAIN EWOULDBLOCK
                std::cout << "Timeout reached" << std::endl;
                send_success(conn_sock_fd);
                close( conn_sock_fd );
                break;
            }
            if (received_len == 0) {
                std::cout << "Closing connection" << std::endl;
                send_success( conn_sock_fd );
                close( conn_sock_fd );
                break;
            }
            request_str.append( buf, received_len );
        }
        std::cout << "read request: " << request_str << std::endl;
        std::map<std::string,std::string> params;
        get_params( request_str, params );
        if ( params.find( "code" ) == params.end() ) {
            rodsLog( LOG_WARNING, "Received request on port %d which did not contain a code parameter", request_port );
            continue;
        }
        std::string code = params["code"];
        if ( params.find( "state" ) == params.end() ) {
            rodsLog( LOG_WARNING, "Received request on port %d which did not contain a state parameter", request_port );
            continue;
        }
        // TODO mutex listeners obj
        std::string state = params["state"];
        if ( listeners->find( state ) == listeners->end() ) {
            rodsLog( LOG_ERROR, "Received request on port %d which contained an unrecognized state value [%s]", request_port, state.c_str() );
            continue;
        }

        // write the code to the listener socket
        int listener_sockfd = listeners->at( state );
        int code_len = code.size();
        write( listener_sockfd, &code_len, sizeof( code_len ) );
        write( listener_sockfd, code.c_str(), code_len );

        // end this listener
        close( listener_sockfd );
        listeners->erase( state );
    }
}

//TODO config settings
const int request_port = 8080;
const int queue_len = 10;
const char *unix_sock_name = "/tmp/irodsoidcipcsock";
// end config settings
int redirect_server()
{
    rodsLog( LOG_NOTICE, "starting redirect server" );

    std::map<std::string,int> listeners; // map of state->socket
    int ipc_sock, ret;
    struct sockaddr_un server_addr;
    memset( &server_addr, 0, sizeof( sockaddr_un ) );

    // we'll use the same msg protocol as plugin messaging. OIDC spec says not to make assumptions about authorization code length
    // if it were standardized, we could use SOCK_SEQPACKET and simplify the logic
    ipc_sock = socket( AF_UNIX, SOCK_STREAM, 0 );
    if ( ipc_sock < 0 ) {
        perror( "error creating Unix socket" );
        return ipc_sock;
    }
    memset( &server_addr, 0, sizeof( server_addr ) );
    server_addr.sun_family = AF_UNIX;
    strncpy( server_addr.sun_path, unix_sock_name, sizeof( server_addr.sun_path ) - 1 );

    ret = unlink( unix_sock_name ); // remove it if it was still there
    if ( ret < 0 ) {
        // ignore this error
        perror( "unlink" );
    }

    ret = bind( ipc_sock, (struct sockaddr *)&server_addr, sizeof(server_addr) );
    if ( ret < 0 ) {
        std::stringstream err_stream;
        err_stream << "binding to unix socket: " << unix_sock_name << " failed: ";
        perror( err_stream.str().c_str()  );
        return ret;
    }
    listen( ipc_sock, queue_len );
    rodsLog( LOG_NOTICE, "redirect ipc server running with queue length of %d", queue_len );

    std::thread req_thread( redirect_server_accept_thread, request_port, &listeners );
    socklen_t addr_size = sizeof( struct sockaddr_un );

    while ( true ) {
        // accepting listeners, which are irods agent-side plugins waiting for auth-callbacks
        int conn_sock = accept( ipc_sock, (struct sockaddr*)&server_addr, &addr_size );
        int msg_len;
        // TODO error handling
        read( conn_sock, &msg_len, sizeof( msg_len ) );
        if ( msg_len == 0 ) {
            rodsLog( LOG_NOTICE, "redirect server received empty connection on domain socket" );
            continue;
        }
        char buf[msg_len + 1];
        memset( buf, 0, msg_len + 1 );
        read( conn_sock, buf, msg_len );
        std::cout << "received callback listener with state identifier: " << buf << std::endl;

        // TODO need some sort of more complex structure in the map, to store a connection time and TTL
        // so connections that have been waiting around to too long are removed from the listener map and closed
        if ( listeners.find( buf ) != listeners.end() ) {
            rodsLog( LOG_ERROR, "received callback listener with duplicate state value" );
            close( conn_sock );
        }
        else {
            listeners.insert( std::pair<std::string,int>( std::string( buf ), conn_sock ) );
        }
    }

    ret = unlink( unix_sock_name );
    if ( ret < 0 ) {
        perror( "unlink" );
    }
    return 0;
}

bool check_redirect_server_running()
{
    int sock = socket( AF_UNIX, SOCK_STREAM, 0 );
    if ( sock < 0 ) return false;
    struct sockaddr_un addr;
    memset( &addr, 0, sizeof( sockaddr_un ) );
    addr.sun_family = AF_UNIX;
    strncpy( addr.sun_path, unix_sock_name, sizeof( addr.sun_path) - 1 );
    int connect_ret = connect( sock, (struct sockaddr*)&addr, sizeof( sockaddr_un ) );
    if ( connect_ret == 0 ) {
        int len = 0;
        write( sock, &len, sizeof( int ) );
        close( sock );
        return true;
    }
    if ( errno == ECONNREFUSED ) {
        return false;
    }
    else {
        // some unexpected error case
        perror( "failed to connect to the redirect server" );
        return false;
    }
}
*/

/*
    State is used to identify the request from the provider
*/
/*
int accept_request( std::string state, std::string& code )
{
    // try a connection to the domain socket, if refused, start up the redirect server
    bool http_server_running = check_redirect_server_running();
    // TODO maybe switch over to regular TCP socket on loopback address
    if ( !http_server_running ) {
        // start the redirect server process
        rodsLog( LOG_NOTICE, "forking new http server" );
        pid_t pid = fork();
        if ( pid < 0 ) {
            perror( "could not fork" );
            return pid;
        }
        else if ( pid == 0 ) {
            // child
            int ret = redirect_server();
            rodsLog( LOG_NOTICE, "redirect_server exited with status: %d", ret );
            return ret;
        }
    }

    // it is running now
    // wait for up to 30 seconds for redirect server to be up

    struct sockaddr_un addr;
    int sock = socket( AF_UNIX, SOCK_STREAM, 0 );
    if ( sock < 0 ) {
        perror( "socket" );
        rodsLog( LOG_ERROR, "error creating socket" );
        return sock;
    }
    memset( &addr, 0, sizeof( addr ) );
    addr.sun_family = AF_UNIX;
    strncpy( addr.sun_path, unix_sock_name, sizeof( addr.sun_path) - 1 );
    rodsLog( LOG_NOTICE, "agent is connecting to http server via domain socket: %s", addr.sun_path );
    int ret;// = connect( sock, (struct sockaddr*)&addr, sizeof( addr ) );
    int waited = 0;
    const int MAX_REDIRECT_SERVER_WAIT = 30;
    while ( waited++ < MAX_REDIRECT_SERVER_WAIT ) {
        ret = connect( sock, (struct sockaddr*)&addr, sizeof( addr ) );
        if ( ret == 0 ) {
            break;
        }
        std::cout << "waiting for redirect server to be up: " << waited << std::endl;
        if ( waited >= MAX_REDIRECT_SERVER_WAIT ) {
            perror( "connect" );
            rodsLog( LOG_ERROR, "timeout reached while waiting for redirect server" );
            return -1;
        }
        std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
    }

    // write state (one time code), to identify our plugin agent to the redirect server
    int state_len = state.size();
    write( sock, &state_len, sizeof( state_len ) );
    write( sock, state.c_str(), state_len );

    // this will block for redirect server, until it returns a msg with the authorization code in it
    read_msg( sock, code );
    std::cout << "got code from redirect server: " << code << std::endl;
    return 0;
}
*/
