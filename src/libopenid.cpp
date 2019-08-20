//#define USE_SSL 1 (libpam.cpp)
#include "sslSockComm.h"
#include "getRodsEnv.h"
#include "authCheck.h"
#include "authPluginRequest.h"
#include "authRequest.h"
#include "authResponse.h"
#include "authenticate.h"
#include "genQuery.h"
#include "irods_auth_constants.hpp"
#include "irods_auth_plugin.hpp"
#include "irods_auth_factory.hpp"
#include "irods_auth_manager.hpp"
#include "irods_client_server_negotiation.hpp"
#include "irods_configuration_keywords.hpp"
#include "irods_error.hpp"
#include "irods_generic_auth_object.hpp"
#include "irods_kvp_string_parser.hpp"
#include "irods_server_properties.hpp"
#include "irods_environment_properties.hpp"
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
#include <random>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <curl/curl.h>
#include <boost/algorithm/string.hpp>
#include "base64.h"
#include "jansson.h"

/*Adding for manual queries to r_user_session_key
 */
//#include "icatStructs.hpp"
//#include "icatHighLevelRoutines.hpp"
//#include "low_level_odbc.hpp"

/************************************************/

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

// OPENID helper methods
bool curl_post( std::string url, std::string *fields, std::vector<std::string> *headers, std::string *response, long *status_code );
bool curl_get( std::string url, std::string *params, std::vector<std::string> *headers, std::string *response, long *status_code );
///END DECLARATIONS

// increases output
static bool openidDebug = true;
// alias log level. in prod set to LOG_DEBUG or LOG_DEBUG3
#define DEBUG_FLAG LOG_NOTICE

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
        //rodsLog( LOG_NOTICE, msg.c_str() );
        puts( msg.c_str() );
    }
}


#include <fstream>
void write_log( const std::string& msg )
{
    std::ofstream logfile( "/tmp/irodsserver.log", std::ios::out | std::ios::app );
    logfile << msg << std::endl;
    logfile.close();
}


/*
    Only systems with HOME defined
*/
irods::error sess_filename( std::string& path_out )
{
    debug( "entering sess_filename()" );
    char path[LONG_NAME_LEN + 1];
    memset( path, 0, LONG_NAME_LEN + 1 );
    debug( "calling getRodsEnvAuthFileName()" );
    char *env = getRodsEnvAuthFileName();
    if ( env != NULL && *env != '\0' ) {
        debug( "found valid env from irods" );
        path_out = std::string( env );
    }
    debug( "trying to call getenv(HOME)" );
    env = getenv( "HOME" );
    if ( env == NULL ) {
        rodsLog( LOG_WARNING, "environment variable HOME not defined" );
        return ERROR( -1, "could not get auth filename" );
    }
    debug( "HOME: " + std::string( env ) );
    strncpy( path, env, strlen( env ) );
    strncat( path, "/", MAX_NAME_LEN - strlen( path ) );
    strncat( path, AUTH_FILENAME_DEFAULT, MAX_NAME_LEN - strlen( path ) );
    path_out = std::string( path );
    return SUCCESS();
}
int write_sess_file( std::string val )
{
    debug( "entering write_sess_file" );
    std::string auth_file;
    irods::error ret = sess_filename( auth_file );
    if ( !ret.ok() ) {
        return -3;
    }
    FILE *fd = fopen( auth_file.c_str(), "w+" );
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
extern "C"
int read_sess_file( std::string& val_out )
{
    debug( "entering read_sess_file" );
    std::string auth_file;
    irods::error ret = sess_filename( auth_file );
    if ( !ret.ok() ) {
        return -3;
    }
    FILE *fd = fopen( auth_file.c_str(), "r" );
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
        boost::trim( val_out );
        //val_out.erase( std::remove(
        //                    val_out.begin(),
        //                    val_out.end(),
        //                    '\n' ),
        //               val_out.end() );
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


static void
sslLogError( const char *msg ) {
    unsigned long err;
    char buf[512];

    while ( ( err = ERR_get_error() ) ) {
        ERR_error_string_n( err, buf, 512 );
        rodsLog( LOG_ERROR, "%s. SSL error: %s", msg, buf );
    }
}


static int
sslVerifyCallback( int ok, X509_STORE_CTX *store ) {
    char data[256];

    /* log any verification problems, even if we'll still accept the cert */
    if ( !ok ) {
        auto *cert = X509_STORE_CTX_get_current_cert( store );
        int  depth = X509_STORE_CTX_get_error_depth( store );
        int  err = X509_STORE_CTX_get_error( store );

        rodsLog( LOG_NOTICE, "sslVerifyCallback: problem with certificate at depth: %i", depth );
        X509_NAME_oneline( X509_get_issuer_name( cert ), data, 256 );
        rodsLog( LOG_NOTICE, "sslVerifyCallback:   issuer = %s", data );
        X509_NAME_oneline( X509_get_subject_name( cert ), data, 256 );
        rodsLog( LOG_NOTICE, "sslVerifyCallback:   subject = %s", data );
        rodsLog( LOG_NOTICE, "sslVerifyCallback:   err %i:%s", err,
                 X509_verify_cert_error_string( err ) );
    }

    return ok;
}


static SSL_CTX*
sslInit( char *certfile, char *keyfile ) {
    static int init_done = 0;
    rodsEnv env;
    int status = getRodsEnv( &env );
    if ( status < 0 ) {
        rodsLog(
            LOG_ERROR,
            "sslInit - failed in getRodsEnv : %d",
            status );
        return NULL;
    }
    if ( !init_done ) {
        SSL_library_init();
        SSL_load_error_strings();
        init_done = 1;
    }

    /* in our test programs we set up a null signal
       handler for SIGPIPE */
    /* signal(SIGPIPE, sslSigpipeHandler); */

    SSL_CTX* ctx = SSL_CTX_new( SSLv23_method() );

    SSL_CTX_set_options( ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_SINGLE_DH_USE );

    /* load our keys and certificates if provided */
    if ( certfile ) {
        if ( SSL_CTX_use_certificate_chain_file( ctx, certfile ) != 1 ) {
            sslLogError( "sslInit: couldn't read certificate chain file" );
            SSL_CTX_free( ctx );
            return NULL;
        }
        else {
            if ( SSL_CTX_use_PrivateKey_file( ctx, keyfile, SSL_FILETYPE_PEM ) != 1 ) {
                sslLogError( "sslInit: couldn't read key file" );
                SSL_CTX_free( ctx );
                return NULL;
            }
        }
    }

    /* set up CA paths and files here */
    const char *ca_path = strcmp( env.irodsSSLCACertificatePath, "" ) ? env.irodsSSLCACertificatePath : NULL;
    const char *ca_file = strcmp( env.irodsSSLCACertificateFile, "" ) ? env.irodsSSLCACertificateFile : NULL;
    if ( ca_path || ca_file ) {
        if ( SSL_CTX_load_verify_locations( ctx, ca_file, ca_path ) != 1 ) {
            sslLogError( "sslInit: error loading CA certificate locations" );
        }
    }
    if ( SSL_CTX_set_default_verify_paths( ctx ) != 1 ) {
        sslLogError( "sslInit: error loading default CA certificate locations" );
    }

    /* Set up the default certificate verification */
    /* if "none" is specified, we won't stop the SSL handshake
       due to certificate error, but will log messages from
       the verification callback */
    const char* verify_server = env.irodsSSLVerifyServer;
    if ( verify_server && !strcmp( verify_server, "none" ) ) {
        SSL_CTX_set_verify( ctx, SSL_VERIFY_NONE, sslVerifyCallback );
    }
    else {
        SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER, sslVerifyCallback );
    }
    /* default depth is nine ... leave this here in case it needs modification */
    SSL_CTX_set_verify_depth( ctx, 9 );

    /* ciphers */
    if ( SSL_CTX_set_cipher_list( ctx, SSL_CIPHER_LIST ) != 1 ) {
        sslLogError( "sslInit: couldn't set the cipher list (no valid ciphers)" );
        SSL_CTX_free( ctx );
        return NULL;
    }

    return ctx;
}


static SSL*
sslInitSocket( SSL_CTX *ctx, int sock ) {
    SSL *ssl;
    BIO *bio;

    bio = BIO_new_socket( sock, BIO_NOCLOSE );
    if ( bio == NULL ) {
        sslLogError( "sslInitSocket: BIO allocation error" );
        return NULL;
    }
    ssl = SSL_new( ctx );
    if ( ssl == NULL ) {
        sslLogError( "sslInitSocket: couldn't create a new SSL socket" );
        BIO_free( bio );
        return NULL;
    }
    SSL_set_bio( ssl, bio, bio );

    return ssl;
}


int ssl_write_msg( SSL* ssl, const std::string& msg )
{
    int msg_len = msg.size();
    SSL_write( ssl, &msg_len, sizeof( msg_len ) );
    SSL_write( ssl, msg.c_str(), msg_len );
    return msg_len;
}


int ssl_read_msg( SSL* ssl, std::string& msg_out )
{
    const int READ_LEN = 256;
    char buffer[READ_LEN + 1];
    int n_bytes = 0;
    int total_bytes = 0;
    int data_len = 0;
    SSL_read( ssl, &data_len, sizeof( data_len ) );
    std::string msg;
    // read that many bytes into our buffer
    while ( total_bytes < data_len ) {
        memset( buffer, 0, READ_LEN + 1 );
        int bytes_remaining = data_len - total_bytes;
        if ( bytes_remaining < READ_LEN ) {
            // can read rest of data in one go
            n_bytes = SSL_read( ssl, buffer, bytes_remaining );
        }
        else {
            // read max bytes into buffer
            n_bytes = SSL_read( ssl, buffer, READ_LEN );
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
        msg.append( buffer );
        total_bytes += n_bytes;
    }
    msg_out = msg;
    return total_bytes;
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
void read_from_server(
        int portno,
        std::string nonce,
        std::string& user_name,
        std::string& session_token )
{
    debug( "entering read_from_server" );
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent* server;
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
    memcpy( &serv_addr.sin_addr.s_addr, server->h_addr, server->h_length );
    serv_addr.sin_port = htons( portno );
    if ( connect( sockfd, (struct sockaddr*)&serv_addr, sizeof( serv_addr ) ) < 0 ) {
        perror( "connect" );
        return;
    }
    // turn on ssl
    SSL_CTX *ctx = sslInit( NULL, NULL );
    if ( !ctx ) {
        rodsLog( LOG_ERROR, "could not initialize SSL context on client" );
        close( sockfd );
        return;
    }
    SSL* ssl = sslInitSocket( ctx, sockfd );
    if ( !ssl ) {
        rodsLog( LOG_ERROR, "could not initialize SSL on client socket" );
        ERR_print_errors_fp( stdout );
        close( sockfd );
        return;
    }
    int status = SSL_connect( ssl );
    if ( status != 1 ) {
        rodsLog( LOG_ERROR, "ssl connect error" );
        SSL_free( ssl );
        SSL_CTX_free( ctx );
        close( sockfd );
        return;
    }
    // TODO peer validation

    // write nonce to server to verify that we are the same client that the auth req came from
    ssl_write_msg( ssl, nonce );

    // read first 4 bytes (data length)
    std::string authorization_url_buf;
    if ( ssl_read_msg( ssl, authorization_url_buf ) < 0 ) {
        perror( "error reading url from socket" );
        return;
    }
    // finished reading authorization url
    // if the auth url is "true", session is already authorized, no user action needed
    // TODO maybe find better way to signal a valid session,
    // debug issue with using empty message as url
    if ( authorization_url_buf.compare( OPENID_SESSION_VALID ) == 0 ) {
        rodsLog( DEBUG_FLAG, "OpenID Session is valid" );
    }
    else {
        std::cout << authorization_url_buf << std::endl;
    }

    // wait for username message now
    if ( ssl_read_msg( ssl, user_name ) < 0 ) {
        perror( "error reading username from server" );
        return;
    }
    debug( "read user_name: " + user_name );

    // wait for session token now
    int len = ssl_read_msg( ssl, session_token );
    if ( len < 0 ) {
        perror( "error reading session token from server" );
        return;
    }
    debug( "read session token: " + session_token );
    debug( "session token length: " + std::to_string( len ) );

    SSL_free( ssl );
    SSL_CTX_free( ctx );
    close( sockfd );
    debug( "leaving read_from_server" );
}


irods::error openid_auth_establish_context(
    irods::plugin_context& _ctx ) {
    irods::error result = SUCCESS();
    irods::error ret;

    ret = _ctx.valid<irods::generic_auth_object>();
    if ( !ret.ok()) {
        return ERROR(SYS_INVALID_INPUT_PARAM, "Invalid plugin context.");
    }
    irods::generic_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::generic_auth_object>( _ctx.fco() );

    return ret;
}

irods::error openid_auth_client_start(
    irods::plugin_context& _ctx,
    rcComm_t*              _comm,
    const char*            _context_string)
{
    debug( "entering openid_auth_client_start" );
    bool got_ctx = false;
    if ( _context_string && *_context_string ) {
        got_ctx = true;
        debug( "openid_auth_client_start,_context_string: " + std::string( _context_string ) );
    }
    else {
        debug( "openid_auth_client_start, no _context_string" );
    }
    irods::error result = SUCCESS();
    irods::error ret;

    ret = _ctx.valid<irods::generic_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context.") ).ok() ) {
        if ( ( result = ASSERT_ERROR( _comm != NULL, SYS_INVALID_INPUT_PARAM, "Null rcComm_t pointer." ) ).ok() ) {
            irods::generic_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::generic_auth_object>( _ctx.fco() );

            // set the user name from the conn
            ptr->user_name( _comm->proxyUser.userName );

            // set the zone name from the conn
            ptr->zone_name( _comm->proxyUser.rodsZone );

            // set the socket from the conn
            ptr->sock( _comm->sock );

            irods::kvp_map_t ctx_map;
            if ( got_ctx ) {
                rodsLog( DEBUG_FLAG, "using provided context string" );
                irods::parse_escaped_kvp_string( _context_string, ctx_map );
                // use an existing context string
                //rodsLog( LOG_NOTICE, "using existing context: %s", _context_string );
                    //ptr->context( _context_string );
            }

            if ( ctx_map.count( "nobuildctx" ) > 0 ) {
                if ( got_ctx ) {
                    // check if iinit_arg was passed from an iinit invocation
                    if ( ctx_map.count( "iinit_arg" ) > 0 ) {
                        irods::kvp_map_t arg_map;
                        ret = irods::parse_escaped_kvp_string( ctx_map["iinit_arg"], arg_map );
                        if ( ret.ok() ) {
                            if ( arg_map.count( "access_token" ) > 0 ) {
                                ctx_map["access_token"] = arg_map["access_token"];
                            }
                            if ( arg_map.count( "user_key" ) > 0 ) {
                                ctx_map["user_key"] = arg_map["user_key"];
                            }
                            std::string new_context_string = irods::escaped_kvp_string( ctx_map );
                            rodsLog( DEBUG_FLAG, "new context using iinit_arg: ", new_context_string.c_str() );
                            ptr->context( new_context_string.c_str() );
                        }
                        else {
                            // the arg passed was not a kvp string
                        }
                    }
                    else {
                        // arg passed did not contain iinit_arg
                        ptr->context( _context_string );
                    }
                }
            }
            else {
                // attempt to update context from client environment it now
                rodsLog( LOG_NOTICE, "attempting to update context from client" );
                //irods::kvp_map_t ctx_map;
                // set the provider config to use, must match a provider configured on server
                try {
                    std::string client_provider_cfg = irods::get_environment_property<std::string&>( "openid_provider" );
                    ctx_map["provider"] = client_provider_cfg;
                    debug( "client using provider: " + ctx_map["provider"] );
                }
                catch ( const irods::exception& e ) {
                    if ( e.code() == KEY_NOT_FOUND ) {
                        rodsLog( LOG_DEBUG, "KEY_NOT_FOUND: openid_provider not defined" );
                    }
                    else {
                        rodsLog( LOG_DEBUG, "unknown error" );
                        irods::log( e );
                    }
                }

                // set existing session from pw file if exists
                std::string sess;
                int sess_ret = read_sess_file( sess );

                if ( sess_ret < 0 || sess.size() == 0 ) {
                    std::cout << "No client session file" << std::endl;
                    debug( "obfGetPw returned: " + std::to_string( sess_ret ) );
                }
                else {
                    debug( "password file contains: " + std::string( sess ) );
                    // set the password in the context string
                    //ctx_map[irods::AUTH_PASSWORD_KEY] = sess;
                    const std::string OPENID_SESS_PREFIX_ACT( "act" );
                    const std::string OPENID_SESS_PREFIX_SID( "sid" );
                    const std::string OPENID_SESS_PREFIX_UKEY( "ukey" );
                    irods::kvp_map_t client_sess_map;
                    irods::parse_escaped_kvp_string( sess, client_sess_map );
                    if ( client_sess_map.count( OPENID_SESS_PREFIX_ACT ) > 0 ) {
                        debug( "adding access_token: " + client_sess_map[OPENID_SESS_PREFIX_ACT] );
                        ctx_map["access_token"] = client_sess_map[OPENID_SESS_PREFIX_ACT];
                    }
                    if ( client_sess_map.count( OPENID_SESS_PREFIX_SID ) > 0 ) {
                        debug( "adding session_id: " + client_sess_map[OPENID_SESS_PREFIX_SID] );
                        ctx_map["session_id"] = client_sess_map[OPENID_SESS_PREFIX_SID];
                    }
                    if ( client_sess_map.count( OPENID_SESS_PREFIX_UKEY ) > 0 ) {
                        debug( "adding user_key: " + client_sess_map[OPENID_SESS_PREFIX_UKEY] );
                        ctx_map["user_key"] = client_sess_map[OPENID_SESS_PREFIX_UKEY];
                    }
                    if ( ctx_map.size() == 0 ) {
                        // fallback
                        ctx_map["session_id"] = sess;
                    }
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
        else {
            debug( "null comm pointer" );
        }
    }
    else {
        debug( "invalid plugin context" );
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
    irods::error result = SUCCESS();
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

    // handle errors and exit
    if ( status < 0 ) {
        result = ERROR( status, "call to rcAuthPluginRequest failed." );
    else {

        irods::kvp_map_t out_map;
        irods::parse_escaped_kvp_string( req_out->result_, out_map );
        debug( "received comm info from server: port: [" + out_map["port"] + "], nonce: [" + out_map["nonce"] + "]" );
        int portno = std::stoi( out_map["port"] );
        std::string nonce = out_map["nonce"]; //

        // perform authorization handshake with server
        // server performs authorization, waits for client to authorize via url it returns via socket
        // when client authorizes, server requests a token from OIDC provider and returns email+session token
        std::string user_name, session_token;
        debug( "attempting to read username and session token from server" );
        read_from_server( portno, nonce, user_name, session_token );
        ptr->user_name( user_name );

        // check if session received is different from session sent
        irods::kvp_map_t context_map;
        ret = irods::parse_escaped_kvp_string( context, context_map );
        if ( !ret.ok() ) {
            rodsLog( LOG_ERROR, "Could not parse context string" );
            result = ERROR( -1, "unable to parse context string after rcAuthPluginRequest" );
        }
        else {
            std::string original_sess = context_map[ irods::AUTH_PASSWORD_KEY ];
            if ( session_token.size() > LONG_NAME_LEN ) {
                throw std::runtime_error( "Session was too long: " + std::to_string( session_token.size() ) );
            }

            // copy it to the authStr field NAME_LEN=64
            strncpy( _comm->clientUser.authInfo.authStr, session_token.c_str(), session_token.size() );

            if ( session_token.size() != 0 && session_token.compare( original_sess ) != 0 ) {
                // server returned a new session token, because existing one is not valid
                // https://github.com/irods-contrib/irods_auth_plugin_openid/issues/5
                // manually reading/writing session file
                //int obfret = obfSavePw( 0, 0, 1, session_token.c_str() );
	        irods::kvp_map_t ctx_map;
		irods::parse_escaped_kvp_string( context, ctx_map );
		// don't rewrite session if nobuildctx passed
		debug( "session_token: " + session_token );
	        if ( ctx_map.count( "nobuildctx" ) == 0 ) {
                    int a = write_sess_file( session_token );
                    debug( "got " + std::to_string( a ) + " from write_sess_file" );
                    if ( a < 0 ) {
                        // don't treat as failure. Even if client doesn't pass nobuildctx, don't fail
                        // just because it couldn't save the session file.
                        rodsLog( LOG_WARNING, "Could not save the auth file for this session" );
                    }
		}
            }
            result = SUCCESS();
        }
    }
    debug( "leaving openid_auth_client_request" );
    if ( req_out ) {
        free( req_out );
    }
    return result;
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

#if OPENSSL_VERSION_NUMBER < 0x10100000
#define ASN1_STRING_get0_data ASN1_STRING_data
#define DH_set0_pqg(dh_, p_, q_, g_) \
    dh_->p = p_; \
    dh_->q = q_; \
    dh_->g = g_;
#endif

static DH*
get_dh2048() {
    static unsigned char dh2048_p[] = {
        0xF6, 0x42, 0x57, 0xB7, 0x08, 0x7F, 0x08, 0x17, 0x72, 0xA2, 0xBA, 0xD6,
        0xA9, 0x42, 0xF3, 0x05, 0xE8, 0xF9, 0x53, 0x11, 0x39, 0x4F, 0xB6, 0xF1,
        0x6E, 0xB9, 0x4B, 0x38, 0x20, 0xDA, 0x01, 0xA7, 0x56, 0xA3, 0x14, 0xE9,
        0x8F, 0x40, 0x55, 0xF3, 0xD0, 0x07, 0xC6, 0xCB, 0x43, 0xA9, 0x94, 0xAD,
        0xF7, 0x4C, 0x64, 0x86, 0x49, 0xF8, 0x0C, 0x83, 0xBD, 0x65, 0xE9, 0x17,
        0xD4, 0xA1, 0xD3, 0x50, 0xF8, 0xF5, 0x59, 0x5F, 0xDC, 0x76, 0x52, 0x4F,
        0x3D, 0x3D, 0x8D, 0xDB, 0xCE, 0x99, 0xE1, 0x57, 0x92, 0x59, 0xCD, 0xFD,
        0xB8, 0xAE, 0x74, 0x4F, 0xC5, 0xFC, 0x76, 0xBC, 0x83, 0xC5, 0x47, 0x30,
        0x61, 0xCE, 0x7C, 0xC9, 0x66, 0xFF, 0x15, 0xF9, 0xBB, 0xFD, 0x91, 0x5E,
        0xC7, 0x01, 0xAA, 0xD3, 0x5B, 0x9E, 0x8D, 0xA0, 0xA5, 0x72, 0x3A, 0xD4,
        0x1A, 0xF0, 0xBF, 0x46, 0x00, 0x58, 0x2B, 0xE5, 0xF4, 0x88, 0xFD, 0x58,
        0x4E, 0x49, 0xDB, 0xCD, 0x20, 0xB4, 0x9D, 0xE4, 0x91, 0x07, 0x36, 0x6B,
        0x33, 0x6C, 0x38, 0x0D, 0x45, 0x1D, 0x0F, 0x7C, 0x88, 0xB3, 0x1C, 0x7C,
        0x5B, 0x2D, 0x8E, 0xF6, 0xF3, 0xC9, 0x23, 0xC0, 0x43, 0xF0, 0xA5, 0x5B,
        0x18, 0x8D, 0x8E, 0xBB, 0x55, 0x8C, 0xB8, 0x5D, 0x38, 0xD3, 0x34, 0xFD,
        0x7C, 0x17, 0x57, 0x43, 0xA3, 0x1D, 0x18, 0x6C, 0xDE, 0x33, 0x21, 0x2C,
        0xB5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29, 0x40, 0x18, 0x11, 0x8D, 0x7C,
        0x84, 0xA7, 0x0A, 0x72, 0xD6, 0x86, 0xC4, 0x03, 0x19, 0xC8, 0x07, 0x29,
        0x7A, 0xCA, 0x95, 0x0C, 0xD9, 0x96, 0x9F, 0xAB, 0xD0, 0x0A, 0x50, 0x9B,
        0x02, 0x46, 0xD3, 0x08, 0x3D, 0x66, 0xA4, 0x5D, 0x41, 0x9F, 0x9C, 0x7C,
        0xBD, 0x89, 0x4B, 0x22, 0x19, 0x26, 0xBA, 0xAB, 0xA2, 0x5E, 0xC3, 0x55,
        0xE9, 0x32, 0x0B, 0x3B,
    };
    static unsigned char dh2048_g[] = {
        0x02,
    };
    auto *dh = DH_new();

    if ( !dh ) {
        return NULL;
    }
    auto* p = BN_bin2bn( dh2048_p, sizeof( dh2048_p ), NULL );
    auto* g = BN_bin2bn( dh2048_g, sizeof( dh2048_g ), NULL );
    if ( !p || !g ) {
        DH_free( dh );
        return NULL;
    }
    DH_set0_pqg(dh, p, nullptr, g);
    return dh;
}


static int
sslLoadDHParams( SSL_CTX *ctx, char *file ) {
    DH *dhparams = NULL;
    BIO *bio;

    if ( file ) {
        bio = BIO_new_file( file, "r" );
        if ( bio ) {
            dhparams = PEM_read_bio_DHparams( bio, NULL, NULL, NULL );
            BIO_free( bio );
        }
    }

    if ( dhparams == NULL ) {
        sslLogError( "sslLoadDHParams: can't load DH parameter file. Falling back to built-ins." );
        dhparams = get_dh2048();
        if ( dhparams == NULL ) {
            rodsLog( LOG_ERROR, "sslLoadDHParams: can't load built-in DH params" );
            return -1;
        }
    }

    if ( SSL_CTX_set_tmp_dh( ctx, dhparams ) < 0 ) {
        sslLogError( "sslLoadDHParams: couldn't set DH parameters" );
        return -1;
    }
    return 0;
}

/*
static irods::error _get_default_openid_provider( std::string& provider )
{
    try {
        const auto default_provider = irods::get_server_property<const std::unordered_map<std::string,boost::any>>(
                            std::vector<std::string>{
                                irods::CFG_PLUGIN_CONFIGURATION_KW,
                                "authentication",
                                "openid",
                                "default_provider"} );
        provider = default_provider;
    }
    catch( const irods::exceptoin& e ) {
        return irods::error( e );
    }
    return SUCCESS();
}
*/

static irods::error _get_openid_port_range( int& min_out, int& max_out )
{
    bool max_defined = false;
    bool min_defined = false;
    int min, max;
    try {
        const auto max_val = irods::get_server_property<const int&>(
                                std::vector<std::string>{
                                irods::CFG_PLUGIN_CONFIGURATION_KW,
                                "authentication",
                                "openid",
                                "token_exchange_max_port" } );
        max = max_val;
        max_defined = true;
    }
    catch ( const irods::exception& e ) {
        // suppress
    }
    try {
        const auto min_val = irods::get_server_property<const int&>(
                                std::vector<std::string>{
                                irods::CFG_PLUGIN_CONFIGURATION_KW,
                                "authentication",
                                "openid",
                                "token_exchange_min_port" } );
        min = min_val;
        min_defined = true;
    }
    catch( const irods::exception& e ) {
        // suppress
    }

    if ( min_defined && max_defined ) {
        if ( max < min ) {
            int t = min;
            min = max;
            max = t;
        }
        min_out = min;
        max_out = max;
        return SUCCESS();
    }
    else if ( !( min_defined && max_defined ) ) {
        min_out = 0;
        max_out = 0; // use random os-assigned ports
        return SUCCESS();
    }
    else if ( !min_defined && max_defined ) {
        return ERROR( SYS_INVALID_INPUT_PARAM, "if token_exchange_max_port is defined, token_exchange_min_port must also be defined" );
    }
    else if ( min_defined && !max_defined ) {
        return ERROR( SYS_INVALID_INPUT_PARAM, "if token_exchange_min_port is defined, token_exchange_max_port must also be defined" );
    }
    
    return ERROR( -1, "Could not get port range for openid" );
}

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

/*
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
*/


/*
    Looks for a server_config.json string corresponding to key, withing hte openid config section.
    Sets buf to its value.
    If the config value for key is not a string, returns an error.
*/
/*
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
*/

/*
    Looks for an array of strings in the openid config section of the server config, with the key "scopes".
    Pushes them into the scopes_out vector.  Does not remove existing contents of scopes_out.
    If no "scopes" key found in this provider's config, returns an error.
*/
/*
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
*/

irods::error openid_auth_agent_start(
    irods::plugin_context& _ctx,
    const char*            _inst_name) {
    rodsLog( DEBUG_FLAG, "entering openid_auth_agent_start" );
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
    rodsLog( DEBUG_FLAG, "leaving openid_auth_agent_start" );
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
    rodsLog( DEBUG_FLAG, "rsModAVUMetadata returned: %d", avu_ret );
    // RESET PRIV LEVEL
    comm->clientUser.authInfo.authFlag = old_auth_flag;

    if ( avu_ret < 0 ) {
        return ERROR( avu_ret, "failed to add metadata for user: " + user_name );
    }
    return SUCCESS();
}

/*
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
*/

/*
irods::error get_subject_id_by_user_name( rsComm_t *comm, std::string user_name, std::string& subject_id )
{
    irods::error ret;
    irods::error result = SUCCESS();
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
        result = ERROR( status, err_stream.str() );
    }
    // DO NOT ALLOW MULTIPLE DN VALUES
    else if ( genQueryOut->rowCnt > 1 ) {
        result = ERROR( -1, "user " + user_name + "has ambiguously defined authentication names" );
        freeGenQueryOut( &genQueryOut );
    }
    else {
        char *value = genQueryOut->sqlResult[1].value;
        subject_id = value;
        freeGenQueryOut( &genQueryOut );
    }

    rodsLog( LOG_NOTICE, "leaving get_subject_id_by_user_name with: %s", user_name.c_str() );
    return SUCCESS();
}
*/

irods::error get_session_id_by_user_name( rsComm_t *comm, std::string user_name, std::string& session_id ) 
{
    irods::error ret;
    irods::error result = SUCCESS();
    rodsLog( LOG_NOTICE, "entering get_session_id_by_user_name: %s", user_name.c_str() );
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof ( genQueryInp_t ) );

    // select
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 1 );
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 1 );
    addInxIval( &genQueryInp.selectInp, COL_USER_DN, 1 );
    addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 1 );

    // where attr name matches
    std::string w1;
    w1 = "='";
    w1 += OPENID_USER_METADATA_SESSION_PREFIX;
    w1 += "'";
    addInxVal( &genQueryInp.sqlCondInp, COL_META_USER_ATTR_NAME, w1.c_str() );

    std::string w2;
    w2 = "='";
    w2 += user_name;
    w2 += "'";
    addInxVal( &genQueryInp.sqlCondInp, COL_USER_NAME, w2.c_str() );

    genQueryInp.maxRows = 2;
    status = rsGenQuery( comm, &genQueryInp, &genQueryOut );
    if ( status == CAT_NO_ROWS_FOUND || status < 0 ) {
        std::ostringstream err_stream;
        err_stream << "No results from rsGenQuery: " << status;
        std::cout << err_stream.str() << std::endl;
        result = ERROR( status, err_stream.str() );
    }
    else {
        char *value = genQueryOut->sqlResult[1].value;
        irods::kvp_map_t meta_map;
        ret = irods::parse_escaped_kvp_string( std::string( value ), meta_map );
        if ( !ret.ok() ) {
            result = ret;
        }
        else {
            session_id = meta_map["session_id"];
        }
        freeGenQueryOut( &genQueryOut );
    }
    rodsLog( LOG_NOTICE, "leaving get_session_id_by_user_name with session_id: %s", session_id.c_str() );
    return result;
}

irods::error user_has_subject_id(
        rsComm_t *comm,
        const std::string& user_name,
        const std::string& subject_id,
        bool *result )
{
    irods::error ret;
    debug( "entering user_has_subject_id with user_name:  " + user_name + ", subject_id: " + subject_id );
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof ( genQueryInp_t ) );

    // select
    //addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 1 );
    //addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 1 );
    addInxIval( &genQueryInp.selectInp, COL_USER_DN, 1 );
    addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 1 );

    // where attr name matches
    std::string w1;
    w1 = "='";
    w1 += user_name;
    w1 += "'";
    addInxVal( &genQueryInp.sqlCondInp, COL_USER_NAME, w1.c_str() );
    
    std::string w2;
    w2 = "='";
    w2 += subject_id;
    w2 += "'";
    addInxVal( &genQueryInp.sqlCondInp, COL_USER_DN, w2.c_str() );

    genQueryInp.maxRows = 2;
    status = rsGenQuery( comm, &genQueryInp, &genQueryOut );
    if ( status == CAT_NO_ROWS_FOUND || status < 0 ) {
        *result = false;
    }
    else {
        *result = true;
        freeGenQueryOut( &genQueryOut );
    }
    debug( "leaving user_has_subject_id with: " + std::to_string( *result ) );
    return SUCCESS();
}

/*
irods::error user_has_session(
        rsComm_t *comm,
        const std::string& user_name,
        const std::string& session_id )
{
    icatSessionStruct *icss;
    int stmtNum = -1;
    int status = -1;
    
    // get db connection struct
    status = chlGetRcs( &icss );
    if ( status < 0 || icss == NULL ) {
        return ERROR( CAT_NOT_OPEN, "failed to connect to icat" );
    }
    
    const char *sql =
    "select s.user_id, s.session_key, s.session_info, s.session_expiry_ts, u.user_name "
    "from r_user_session_key as s "
    "left join r_user_main u on s.user_id = u.user_id "
    "where s.auth_scheme = 'openid';";

    cllExecSqlWithResult( icss, &stmtNum, sql );
}
*/

irods::error validate_user_key(
        const std::string& user_key,
        const std::string& subject_id_in,
        const std::string& user_name_in,
        bool& is_valid,
        long& status_code,
        std::string& subject_id )
{
    irods::error result = SUCCESS();
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

    // query apikey resource
    url += "/apikey/verify";

    // add params
    std::string params;
    if ( user_key.size() != 0 ) {
        params += "key=" + user_key;
    }
    else {
        return ERROR( SYS_INVALID_INPUT_PARAM, "user_key cannot be empty" );
    }

    if ( subject_id_in.size() != 0 ) {
        params += "&uid=" + subject_id_in;
    }
    if ( user_name_in.size() != 0 ) {
        params +=  "&username=" + user_name_in;
    }

    // create headers
    std::vector<std::string> headers;
    std::string authorization_header = "Authorization: Basic ";
    authorization_header += api_key;
    headers.push_back( authorization_header );

    std::string curl_resp;
    bool curl_ret = curl_get( url, &params, &headers, &curl_resp, &status_code );
    if ( !curl_ret ) {
        rodsLog( LOG_ERROR, "failed request to url %s, returned status %ld", url.c_str(), status_code );
        return ERROR( -1, "failure in curl request to token service" );
    }
    else {
        rodsLog( LOG_NOTICE, "request to token_service succeeded" );
    }

    if ( status_code != 200 ) {
        std::ostringstream err_msg;
        err_msg << "token service returned " << status_code << std::endl << curl_resp << std::endl;
        rodsLog( LOG_ERROR, err_msg.str().c_str() );

        if ( status_code == 401 ) {
            is_valid = false;
            return SUCCESS();
        }
    }

    json_error_t json_err;
    json_t *resp_root = json_loads( curl_resp.c_str(), 0, &json_err );
    if ( resp_root == NULL ) {
        std::ostringstream msg( "error parsing response from token service: " );
        msg << json_err_message( json_err );
        std::cout << "status code: " << status_code;
        std::cout << std::endl << "response: "  << curl_resp;
        rodsLog( LOG_ERROR, msg.str().c_str() );
        return ERROR( -1, msg.str() );
    }
    
    json_t *valid_obj = json_object_get( resp_root, "valid" );
    if ( json_is_boolean( valid_obj ) ) {
        is_valid = json_boolean_value( valid_obj );
    }
    else {
        json_decref( resp_root );
        return ERROR( -1, "no valid field returned in user key validation" );
    }

    // if not valid stop
    if ( !is_valid ) {
        json_decref( resp_root );
        return SUCCESS();
    }

    json_t *uid_obj = json_object_get( resp_root, "uid" );
    if ( json_is_string( uid_obj ) ) {
        subject_id = json_string_value( uid_obj );
    }
    else {
        json_decref( resp_root );
        return ERROR( -1, "no uid field returned in user key validation" );
    }
    json_decref( resp_root );
    return SUCCESS();
}

irods::error validate_user_token(
        rsComm_t *comm,
        const std::string& user_name,
        const std::string& provider,
        const std::string& token,
        bool& is_valid,
        long& status_code,
        std::string& subject_id )
{
    irods::error result = SUCCESS();
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
    url += "/validate_token";

    // add params conditionally
    std::string params;

    if ( provider.size() != 0 ) {
        params += "provider=" + provider;
    }
    else {
        return ERROR( SYS_INVALID_INPUT_PARAM, "provider cannot be empty" );
    }
    
    if ( token.size() != 0 ) {
        params += "&access_token=" + token;
    }
    else {
        return ERROR( SYS_INVALID_INPUT_PARAM, "token cannot be empty" );
    }

    // create headers
    std::vector<std::string> headers;
    std::string authorization_header = "Authorization: Basic " + api_key;
    headers.push_back( authorization_header );
    
    std::string curl_resp;
    bool curl_ret = curl_get( url, &params, &headers, &curl_resp, &status_code );
    if ( !curl_ret ) {
        rodsLog( LOG_ERROR, "failed request to url %s, returned status %ld", url.c_str(), status_code );
        return ERROR( -1, "failure in curl request to token service" );
    }
    else {
        rodsLog( LOG_NOTICE, "request to token_service succeeded" );
    }
   
    if ( status_code != 200 ) {
        std::ostringstream err_msg;
        err_msg << "token service returned " << status_code << std::endl << curl_resp << std::endl;
        rodsLog( LOG_ERROR, err_msg.str().c_str() );
        return ERROR( -1, err_msg.str() );
    }

    json_error_t json_err;
    json_t *resp_root = json_loads( curl_resp.c_str(), 0, &json_err );
    if ( resp_root == NULL ) {
        std::ostringstream msg( "error parsing response from token service: " );
        msg << json_err_message( json_err );
        std::cout << "status code: " << status_code << std::endl << "response: " << curl_resp;
        rodsLog( LOG_ERROR, msg.str().c_str() );
        return ERROR( -1, msg.str() );
    }

    json_t *active_obj = json_object_get( resp_root, "active" );
    if ( json_is_boolean( active_obj ) ) {
        is_valid = json_boolean_value( active_obj );
    }
    else {
        json_decref( resp_root );
        return ERROR( -1, "no active field returned in token validation" );
    }

    if ( !is_valid ) {
        json_decref( resp_root );
        return SUCCESS();
    }

    json_t *sub_obj = json_object_get( resp_root, "sub" );
    if ( json_is_string( sub_obj ) ) {
        subject_id = json_string_value( sub_obj );
    }
    else {
        json_decref( resp_root );
        return ERROR( -1, "no sub field returned in token validation" );
    }
    // see if this is a valid subject id for the user
    bool user_has_sub = false;
    ret = user_has_subject_id( comm, user_name, subject_id, &user_has_sub );
    if ( !ret.ok() ) {
        rodsLog( LOG_ERROR, "user_has_subject_id failed" );
        is_valid = false;
        result = ret;
    }

    // query succeeded, now update is_valid appropriately. result only means query succeeded
    if ( user_has_sub ) {
        is_valid = true;
        result = SUCCESS();
    }
    else {
        rodsLog( LOG_WARNING, "User does not have subject id corresponding to this openid token" );
        is_valid = false;
        result = SUCCESS();
    }
    json_decref( resp_root );
    debug( "leaving validate_user_token" );
    return SUCCESS();
}


/* Returns a 1 if the session exists for the user, otherwise 0
 */
int validate_user_session(
        rsComm_t *comm,
        const std::string& user_name,
        const std::string& session_id )
{
    int result = 0;
    irods::error ret = SUCCESS();
    debug( "entering validate_user_session with session_id: " + session_id
            + ", user_name: " + user_name );
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

    // select
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 1 );
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 1 );
    addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 1 );

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
    
    std::string w3;
    w3 = "='";
    w3 += user_name;
    w3 += "'";
    addInxVal( &genQueryInp.sqlCondInp, COL_USER_NAME, w3.c_str() );

    genQueryInp.maxRows = 2;
    status = rsGenQuery( comm, &genQueryInp, &genQueryOut );
    if ( status == CAT_NO_ROWS_FOUND || status < 0 ) {
        std::stringstream err_stream;
        err_stream << "No results from rsGenQuery: " << status;
        std::cout << err_stream.str() << std::endl;
        result = 0;
    }
    else {
        result = 1;
        freeGenQueryOut( &genQueryOut );
    }
    debug( "leaving validate_user_session" );
    return result;
}


irods::error get_subject_id_by_session_id( rsComm_t *comm, std::string session_id, std::string& subject_id )
{
    irods::error ret;
    irods::error result = SUCCESS();
    debug( "entering get_subject_id_by_session_id with: " + session_id );
    if ( session_id.size() == 0 ) {
        return ERROR( SYS_INVALID_INPUT_PARAM, "session_id was empty" );
    }
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

    // select
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 1 );
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 1 );
    addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 1 );

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
        result = ERROR( status, err_stream.str() );
    }
    else {
        char *value = genQueryOut->sqlResult[1].value;
        irods::kvp_map_t meta_map;
        ret = irods::parse_escaped_kvp_string( std::string( value ), meta_map );
        if ( !ret.ok() ) {
            result =ret;
        }
        else {
            subject_id = meta_map["subject_id"];
        }
        freeGenQueryOut( &genQueryOut );
    }
    debug( "leaving get_subject_id_by_session_id with subject_id: " + subject_id );
    return result;
}


irods::error get_username_by_session_id( rsComm_t *comm, std::string session_id, std::string *user_name )
{
    debug( "entering get_username_by_session_id with: " + session_id );
    irods::error result = SUCCESS();
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

    // select
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 1 );
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 1 );
    addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 1 );

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
        result = ERROR( status, err_stream.str() );
    }
    else {
        // do quick sanity check
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
                std::string errmsg = "While looking up username by session_id, found multiple users for one session: "
                                        + session_id;
                rodsLog( LOG_ERROR, errmsg.c_str() );
                result = ERROR( SYS_INVALID_INPUT_PARAM, errmsg );
            }
        }
        *user_name = user_buf;
        rodsLog( LOG_NOTICE, "query for username by session_id returned: %s", user_buf );
        freeGenQueryOut( &genQueryOut );
    }

    debug( "returning from get_username_by_session_id" );
    return result;
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
    debug( "entering get_token_meta_id" );
    irods::error result = SUCCESS();
    int status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut;
    memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

    // select
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_ID, 1 );
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_NAME, 1 );
    addInxIval( &genQueryInp.selectInp, COL_META_USER_ATTR_VALUE, 1 );

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
        result = ERROR( status, err_stream.str() );
    }
    else if ( genQueryOut->rowCnt > 1 ) {
        std::stringstream err_stream;
        err_stream << "Multiple metadata ids found for (user,sess,scope): (";
        err_stream << user_name << ",";
        err_stream << session_id << ",";
        err_stream << scope << ")";
        std::cout << err_stream.str() << std::endl;
        result = ERROR( -1, err_stream.str() );
        freeGenQueryOut( &genQueryOut );
    }
    else {
        char *id = genQueryOut->sqlResult[0].value + ( 0 * genQueryOut->sqlResult[0].len );
        meta_id = id;
        freeGenQueryOut( &genQueryOut );
    }
    debug( "leaving get_token_meta_id" );
    return result;
}


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
        long *status_code,
        json_t **resp_root )
{
    rodsLog( LOG_NOTICE, "entering _token_service_get" );
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
    
    if ( *status_code != 200 && *status_code != 401 ) {
        std::ostringstream err_msg;
        err_msg << "token service returned " << *status_code << std::endl << curl_resp << std::endl;
        rodsLog( LOG_ERROR, err_msg.str().c_str() );
        return ERROR( -1, err_msg.str() );
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
    std::cout << "entering token_service_get_url, provider: " << provider << ", scope: " << scope << std::endl;
    return _token_service_get( "", provider, scope, "", status_code, resp_root );
}

irods::error token_service_get_by_nonce(
        std::string provider,
        std::string scope,
        std::string nonce,
        long *status_code,
        json_t **resp_root )
{
    std::cout << "entering token_service_get_by_nonce" << std::endl;
    return _token_service_get( "", provider, scope, nonce, status_code, resp_root );
}

irods::error token_service_get_by_subject(
        std::string subject_id,
        std::string provider,
        std::string scope,
        long *status_code,
        json_t **resp_root )
{
    std::cout << "entering token_service_get_by_subject" << std::endl;
    return _token_service_get( subject_id, provider, scope, "", status_code, resp_root );
}


/*  Need to synchronize between client and server.
    Do not return from auth agent request until a port is open on the server because
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
int bind_port( int min_port, int max_port, int *port_out, int *sock_out )
{
    int sockfd;
    struct sockaddr_in serv_addr;
    sockfd = socket( AF_INET, SOCK_STREAM, 0 );
    if ( sockfd < 0 ) {
        perror( "socket" );
        return sockfd;
    }
    int ret = -1;
    int opt_val = 1;
    setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&opt_val, sizeof( opt_val ) );
    memset( &serv_addr, 0, sizeof( serv_addr ) );
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    // single port specified (min==max)
    if ( min_port == max_port ) {
        serv_addr.sin_port = htons( min_port );
        ret = bind( sockfd, (struct sockaddr*)&serv_addr, sizeof( serv_addr ) );
        if ( ret < 0 ) {
            std::stringstream err_stream( "error binding socket to port: " );
            err_stream << min_port;
            perror( err_stream.str().c_str() );
            close( sockfd );
            return ret;
        }
        *port_out = min_port;
        if ( min_port == 0 ) {
            socklen_t socklen = sizeof( serv_addr );
            ret = getsockname( sockfd, (struct sockaddr*)&serv_addr, &socklen );
            if ( ret < 0 ) {
                close( sockfd );
                perror( "error looking up socket for OS assigned port" );
                return ret;
            }
            int assigned_port = ntohs( serv_addr.sin_port );
            rodsLog( DEBUG_FLAG, "assigned port: %d", assigned_port );
            *port_out = assigned_port;
        }
    }
    else {
        // random range
        std::vector<int> ports;
        for ( int i = min_port; i <= max_port; i++ ) {
            ports.push_back( i );
        }
        //auto rng = randint;
        std::srand( time( NULL ) );
        auto rng = [](int i){ return std::rand() % i; };
        //rng.seed( time( NULL ) );
        std::random_shuffle( ports.begin(), ports.end(), rng );
        bool bound = false;
        for ( auto iter = ports.begin(); iter != ports.end(); iter++ ) {
            serv_addr.sin_port = htons( *iter );
            ret = bind( sockfd, (struct sockaddr*)&serv_addr, sizeof( serv_addr ) );
            if ( ret == 0 ) {
                bound = true;
                *port_out = *iter;
                rodsLog( DEBUG_FLAG, "bound random port: %d in range: [%d, %d]", *iter, min_port, max_port );
            }
        }
        if ( !bound ) {
            rodsLog( LOG_ERROR, "could not bind any ports in range: [%d, %d]", min_port, max_port );
            return -1;
        }
    }
    listen( sockfd, 1 );

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
        std::string access_token,
        std::string session_id,
        std::string user_key,
        std::string user_name,
        bool reprompt )
{
    std::unique_lock<std::mutex> lock(port_mutex);

    rodsLog( DEBUG_FLAG, "entering open_write_to_port with session_id: %s", session_id.c_str() );
    irods::error ret;
    int r;
    //////////////
    int sockfd, conn_sockfd;
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    clilen = sizeof( cli_addr );
    
    // see if there is a range defined
    int min, max;
    ret = _get_openid_port_range( min, max );
    if ( !ret.ok() ) {
        rodsLog( LOG_ERROR, "open_write_to_port: failed to get port range" );
        return;
    }
    r = bind_port( min, max, portno, &sockfd );
    if ( r < 0 ) {
        perror( "error binding to port" );
        throw std::runtime_error( "could not bind to port" );
    }
    rodsLog( DEBUG_FLAG, "bound to port: %d", *portno );

    // it would be nice to reuse irods helper functions like ssl_init_socket, but they are all static
    rodsEnv env;
    int status = getRodsEnv( &env );
    if ( status < 0 ) {
        rodsLog( LOG_ERROR, "getRodsEnv failed: %d", status );
        close( sockfd );
        throw std::runtime_error( "getRodsEnv failed: " + std::to_string( status ) );
    }

    SSL_CTX *ctx = sslInit( 
            env.irodsSSLCertificateChainFile,
            env.irodsSSLCertificateKeyFile );
    rodsLog( DEBUG_FLAG, "initialized ssl context" );
    if ( !ctx ) {
        std::cout << "failed to establish SSL context" << std::endl;
        ERR_print_errors_fp( stdout );
        throw std::runtime_error( "failed to establish SSL context" );
    }

    status = sslLoadDHParams( ctx, env.irodsSSLDHParamsFile );
    if ( status ) {
        rodsLog( LOG_ERROR, "error loading DH params" );
    }

    /////////////

    // notify that port is open so that main thread can continue and return
    rodsLog( DEBUG_FLAG, "notifying port_is_open_cond" );
    port_opened = true;
    lock.unlock();
    port_is_open_cond.notify_all();

    // wait for a client connection
    conn_sockfd = accept( sockfd, (struct sockaddr*) &cli_addr, &clilen );
    rodsLog( DEBUG_FLAG, "accepted tcp connection" );
    //SSL *ssl = SSL_new( ctx );
    //SSL_set_fd( ssl, conn_sockfd );
    SSL* ssl = sslInitSocket( ctx, conn_sockfd );
    rodsLog( DEBUG_FLAG, "initialized ssl socket" );
    if ( !ssl ) {
        rodsLog( LOG_ERROR, "could not initialize SSL on socket" );
        ERR_print_errors_fp( stdout );
        throw std::runtime_error( "could not initialize SSL on socket" );
    }    
    status = SSL_accept( ssl );
    rodsLog( DEBUG_FLAG, "accepted ssl handshake" );
    if ( status != 1 ) {
        char buf[120];
        int ssl_error_code = SSL_get_error( ssl, status );
        ERR_error_string( ssl_error_code, buf );
        rodsLog( LOG_ERROR, "Error accepting SSL connection: %d, %s", status, buf );
        ERR_print_errors_fp( stdout );
        SSL_free( ssl );
        SSL_CTX_free( ctx );
        throw std::runtime_error( "Error accepting SSL connection" );
    }

    // verify client nonce matches the nonce we sent back from auth_agent_request
    std::string client_nonce;
    if ( ssl_read_msg( ssl, client_nonce ) < 0 ) {
        perror( "error reading nonce from client" );
        SSL_free( ssl );
        SSL_CTX_free( ctx );
        close( conn_sockfd );
        close( sockfd );
        return;
    }
    rodsLog( DEBUG_FLAG, "received nonce from client: %s", client_nonce.c_str() );

    if ( nonce.compare( client_nonce ) != 0 ) {
        rodsLog( LOG_WARNING,
                 "Received connection on port %d from with invalid nonce. Expected [%s] but got [%s]",
                 *portno,
                 nonce.c_str(),
                 client_nonce.c_str() );
        throw std::runtime_error( "client connection failed authentication" );
    }
    std::string msg;
    bool authorized = false;
    json_t *resp_root = NULL;
    long status_code = -1;
    std::string subject_id;

    // user_key takes precedent over access_token which takes precedent over session_id
    if ( !user_key.empty() ) {
        // check user key
        bool is_valid = false;
        ret = validate_user_key(
            user_key,
            subject_id,
            "",
            is_valid,
            status_code,
            subject_id );

        //ret = validate_user_key( user_key, is_valid, status_code, subject_id );
        authorized = is_valid;
    }
    else if ( !access_token.empty() ) {
        bool is_valid = false;
        ret = validate_user_token( comm, user_name, openid_provider_name, access_token, is_valid, status_code, subject_id );
        authorized = is_valid;
        if ( is_valid ) {
            rodsLog( LOG_NOTICE, "access_token is valid" );
            json_t *sub_obj = json_object_get( resp_root, "uid" );
            if ( json_is_string( sub_obj ) && subject_id.empty() ) {
                rodsLog( LOG_NOTICE, "setting subject id from token validation" );
                subject_id = json_string_value( sub_obj );
            }
        }
        else {
            rodsLog( LOG_WARNING, "access_token is not valid" );
            subject_id = "";
        }
    }
    else {
        // check if the session is valid in irods icat, ignore subject_id here
        // if not, reauthenticate from scratch and create new metadata entry
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
        rodsLog( DEBUG_FLAG, "session had subject_id: %s", subject_id.c_str() );
    }

    // check if the session is valid in the token service
    if ( subject_id.size() > 0 ) {
        ret = token_service_get_by_subject( subject_id, openid_provider_name, "openid", &status_code, &resp_root );
        if ( !ret.ok() ) {
            std::cout << "first token_service_get failed" << std::endl;
            json_decref( resp_root );
            //return ret;
            rodsLog( LOG_ERROR, ret.result().c_str() );
            msg = "error checking session validity";
            ssl_write_msg( ssl, msg );
            SSL_free( ssl );
            SSL_CTX_free( ctx );
            close( conn_sockfd );
            close( sockfd );
            delete write_thread;
            write_thread = NULL; 
            return;
        }
        json_t *uid_obj = json_object_get( resp_root, "uid" );
        bool got_uid = json_is_string( uid_obj );
        json_t *access_token_obj = json_object_get( resp_root, "access_token" );
        if ( json_is_string( access_token_obj ) ) {
            access_token = json_string_value( access_token_obj );
        }
        bool user_has_uid = false;
        ret = user_has_subject_id(
                        comm,
                        user_name,
                        std::string( json_string_value( uid_obj ) ),
                        &user_has_uid );
        if ( got_uid && user_has_uid ) {
            rodsLog( LOG_NOTICE, "session is valid for this user" );
            authorized = true;
            subject_id = json_string_value( uid_obj );
        }
        else {
            authorized = false;
            rodsLog( LOG_ERROR, "session was valid but uid did not belong to this iRODS user" );
        }
    }
    //std::cout << "authorized: " << authorized << std::endl;
    //std::cout << "status_code: " << status_code << std::endl;
    if ( authorized && status_code == 200 ) {
        rodsLog( DEBUG_FLAG, "session authorized and token service returned 200" );
        // this user has an icat session and still has an active session in the token microservice (not revoked or expired)
        
        // send back SUCCESS
        msg = OPENID_SESSION_VALID;
        ssl_write_msg( ssl, msg );

        // send back user_name
        ssl_write_msg( ssl, user_name );

        // send back session info
        irods::kvp_map_t sess_map;
        // preference is user_key->session_id->access_token
        if ( !user_key.empty() ) {
            sess_map["ukey"] = user_key;
        }
        else if ( !session_id.empty() ) {
            sess_map["sid"] = session_id;
        }
        else if ( !access_token.empty() ) {
            sess_map["act"] = access_token;
        }
        std::string sess = irods::escaped_kvp_string( sess_map );
        ssl_write_msg( ssl, sess );

        rodsLog( LOG_NOTICE, "wrote (msg,user,sess) to client: (%s,%s,%s)",
                OPENID_SESSION_VALID.c_str(),
                user_name.c_str(),
                sess.c_str() );
    } 
    if ( !authorized || status_code == 401 ) {
        rodsLog( LOG_NOTICE, "not authorized, user must re-authenticate" );
        if ( !reprompt ) {
            ssl_write_msg( ssl, "not authorized, user must re-authenticate" );
            SSL_free( ssl );
            SSL_CTX_free( ctx );
            close( conn_sockfd );
            close( sockfd );
            return;
        }
        // user either wasn't provided, wasn't valid, or the session was deactivated/invalid
        // user must re-authenticate
        ret = token_service_get_url( openid_provider_name, "openid", &status_code, &resp_root );
        if ( json_is_string( json_object_get( resp_root, "authorization_url" ) ) ) {
            msg = json_string_value( json_object_get( resp_root, "authorization_url" ) );
            rodsLog( DEBUG_FLAG, "token service returned authorization url: [%s]", msg.c_str() );
        }
        else {
            rodsLog( DEBUG_FLAG, "no authorization url returned from token service" );
            char *resp = json_dumps( resp_root, JSON_INDENT(2) );
            rodsLog( DEBUG_FLAG, "%s", resp );
            free( resp );
            rodsLog( LOG_ERROR, "could not parse response from token service" );
            SSL_free( ssl );
            SSL_CTX_free( ctx );
            close( conn_sockfd );
            close( sockfd );
            return;
        }

        // send back auth url and poll for response
        // if 200 send back [username, session id]
        // else send back [FAILURE, FAILURE]
        ssl_write_msg( ssl, msg );

        // block against token service for 60 seconds
        json_t *poll_resp_root;
        long poll_status_code;
        std::string nonce;
        ret = parse_nonce_from_authorization_url( msg, nonce );
        size_t count = 20; // TODO make configurable
        size_t interval = 3; // poll every 3 sec for 1 min
        for ( size_t i = 0; i < count; i++ ) {
            rodsLog( DEBUG_FLAG, "polling token service for nonce, count: %ld", i );
            ret = token_service_get_by_nonce( openid_provider_name, "openid", nonce, &poll_status_code, &poll_resp_root );
            rodsLog( LOG_NOTICE, ret.result().c_str() );
            if ( poll_status_code < 400 ) {
                break;
            }
            else {
                std::this_thread::sleep_for( std::chrono::seconds( interval ) );
            }
        }
        
        //ret = token_service_get_by_nonce( openid_provider_name, "openid", nonce, 60, &block_status_code, &block_resp_root );
        if ( !ret.ok() ) {
            //json_decref( resp_root );
            rodsLog( LOG_ERROR, ret.result().c_str() );
        }
        
        if ( poll_status_code == 200 ) {
            // user logged in within 60 second limit
            json_t *token_obj = json_object_get( poll_resp_root, "access_token" );
            if ( json_is_string( token_obj ) ) {
                access_token = json_string_value( token_obj );
            }
            else {
                // malformed response from token service
                rodsLog( LOG_ERROR, "no access_token in response from token service" );
            }
            json_t *uid_obj = json_object_get( poll_resp_root, "uid" );
            if ( json_is_string( token_obj ) && json_is_string( uid_obj ) ) {
                subject_id = json_string_value( uid_obj );
                // see if session id already exists for this user
                std::string existing_session_id;
                ret = get_session_id_by_user_name( comm, user_name, existing_session_id );
                rodsLog( LOG_NOTICE, "user [%s] has session id [%s]", user_name.c_str(), existing_session_id.c_str() );
                if ( !ret.ok() || existing_session_id.size() == 0 ) {
                    // no session id exists for this user
                    rodsLog( LOG_NOTICE, "no session exists for this client, creating new entry" );
                    char access_token_sha256[ 33 ];
                    _sha256_hash( access_token, access_token_sha256 );
                    std::cout << "sha256 token hex: ";
                    for ( int i = 0; i < 32; i++ ) {
                        printf( "%02X", (unsigned char)access_token_sha256[i] );
                    }
                    std::cout << std::endl;
                    
                    // truncate hex to 50 char from 64 because davrods limts to 63 char pw
                    // but irods obf technically limits to 50.
                    _hex_from_binary( access_token_sha256, 32, session_id );
                    session_id.resize( 50 );

                    // write this new session to the database 
                    std::string metadata_key = OPENID_USER_METADATA_SESSION_PREFIX;
                    irods::kvp_map_t meta_map;
                    meta_map["subject_id"] = subject_id;
                    meta_map["session_id"] = session_id;
                    std::string meta_val = irods::escaped_kvp_string( meta_map );
                    ret = add_user_metadata( comm, user_name, metadata_key, meta_val );
                    // TODO handle return
                }
                else {
                    // already has session id
                    rodsLog( LOG_NOTICE, "using existing session_id" );
                    session_id = existing_session_id;
                }
                // send back the user name
                ssl_write_msg( ssl, user_name );

                // send back the session id
                irods::kvp_map_t sess_map;
                if ( !session_id.empty() ) {
                    sess_map["sid"] = session_id;
                }
                if ( !access_token.empty() ) {
                    sess_map["act"] = access_token;
                }
                std::string sess = irods::escaped_kvp_string( sess_map );
                ssl_write_msg( ssl, sess );

                rodsLog( LOG_NOTICE, "wrote (msg,user,sess) to client: (%s,%s,%s)",
                        msg.c_str(),
                        user_name.c_str(),
                        sess.c_str() );
            }
            else {
                rodsLog( LOG_ERROR, "could not parse response from token service on polling for valid token" );
                // TODO cleanly cut connection with client
            }
            json_decref( poll_resp_root );
        }
        else {
            rodsLog( LOG_ERROR, "token service returned status [%ld] on polling for token", poll_status_code );
            // token service did not detect a login callback TODO
        }
    }
    else {
        rodsLog( DEBUG_FLAG, "token service returned status [%ld] on initial token request", status_code );
    }
    
    // free json from first call to token service
    if ( resp_root ) {
        json_decref( resp_root );
    }

    // close client connection
    if ( ssl ) {
        SSL_free( ssl );
    }
    if ( ctx ) {
        SSL_CTX_free( ctx );
    }
    close( conn_sockfd );

    // close server socket
    close( sockfd );
    rodsLog( DEBUG_FLAG, "leaving open_write_to_port" );
    // done writing, reset thread pointer; // looks like agents are fresh processes, so this can be changed
    delete write_thread;
    write_thread = NULL;
}


// server receives request from client
// called from rsAuthAgentRequest, which is called by rcAuthAgentRequest
irods::error openid_auth_agent_request(
    irods::plugin_context& _ctx )
{
    rodsLog( DEBUG_FLAG, "entering openid_auth_agent_request" );
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
        rodsLog( DEBUG_FLAG, "auth_agent_request got context: %s", ctx_str.c_str() );
        irods::kvp_map_t ctx_map;
        ret = irods::parse_escaped_kvp_string( ctx_str, ctx_map );
        if ( !ret.ok() ) {
            rodsLog( LOG_ERROR, "Could not parse context string sent from client: %s", ctx_str.c_str() );
            return PASS( ret );
        }
        std::string session_id;
        if ( ctx_map.count( "session_id" ) ) {
            session_id = ctx_map["session_id"];
            rodsLog( LOG_NOTICE, "openid agent received client session: [%s]", session_id.c_str() );
        }
        std::string access_token;
        if ( ctx_map.count( "access_token" ) ) {
            access_token = ctx_map["access_token"];
            rodsLog( LOG_NOTICE, "openid agent received client token: [%s]", access_token.c_str() );
        }
        std::string user_key;
        if ( ctx_map.count( "user_key" ) ) {
            user_key = ctx_map["user_key"];
            rodsLog( LOG_NOTICE, "openid agent received client key: [%s]", user_key.c_str() );
        }

        std::string user_name = ctx_map[irods::AUTH_USER_KEY];
        // set global field to the value the client requested
        if ( ctx_map.count( "provider" ) ) {
            openid_provider_name = ctx_map["provider"];
            rodsLog( LOG_NOTICE, "openid agent received client provider: [%s]", openid_provider_name.c_str() );
        }
        else {
            // attempt to pull default provider
            ret = _get_openid_config_string( "default_provider", openid_provider_name );
            if ( !ret.ok() ) {
                rodsLog( LOG_ERROR, "no provider specified by client and no default_provider configured on server" );
                return ret;
            }
            rodsLog( LOG_NOTICE, "openid agent used default provider" );
        }

        // default to reprompting upon invalid session
        // client can pass reprompt=0 to disable this, in which case
        // one error message will be sent back, and then the connection terminated
        bool reprompt = true;
        if ( ctx_map.count( "reprompt" ) > 0 && ctx_map["reprompt"] == "0" ) {
            reprompt = false;
        }

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
                            access_token,
                            session_id,
                            user_key,
                            user_name,
                            reprompt);
        while ( !port_opened ) {
            port_is_open_cond.wait(lock);
            std::cout << "cond woke up" << std::endl;
        }
        std::cout << "main thread received portno: " << portno << std::endl;
        irods::kvp_map_t return_map;
        std::string port_str = std::to_string( portno );
        return_map["port"] = port_str;
        return_map["nonce"] = nonce; // client plugin must send this as first message when connecting to port
        std::string result_string = irods::escaped_kvp_string( return_map );
        write_log( "request_result: " + result_string );
        rodsLog( LOG_NOTICE, "request_result: %s", result_string.c_str() );
        ptr->request_result( result_string );
        write_thread->detach();

    } // end context check

    rodsLog( DEBUG_FLAG, "leaving openid_auth_agent_request" );
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
    authResponseInp_t* _resp )
{
    rodsLog( DEBUG_FLAG, "entering openid_auth_agent_response" );
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

    rodsLog( DEBUG_FLAG, "leaving openid_auth_agent_response" );
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
