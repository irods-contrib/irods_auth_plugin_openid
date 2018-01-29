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
#include "irods_openid_object.hpp"
#include "irods_client_server_negotiation.hpp"
#include "irods_configuration_keywords.hpp"
#include "irods_error.hpp"
//#include "irods_generic_auth_object.hpp"
#include "irods_kvp_string_parser.hpp"
#include "irods_server_properties.hpp"
#include "irods_stacktrace.hpp"
#include "miscServerFunct.hpp"
#include "rodsErrorTable.h"
#include "rodsLog.h"

#include "openid.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/format.hpp>

#ifdef RODS_SERVER
#include "rsGenQuery.hpp"
#include "rsAuthCheck.hpp"
#include "rsAuthResponse.hpp"
#include "rsAuthRequest.hpp"
#endif


#include <openssl/md5.h>
#include <gssapi.h>
#include <string>

irods::error openid_auth_establish_context(
    irods::plugin_context& _ctx )
{
    irods::error result = SUCCESS();
    irods::error ret;

    ret = _ctx.valid<irods::openid_auth_object>();
    if ( !_ctx.valid<irods::openid_auth_object>().ok())
    {
        return ERROR(SYS_INVALID_INPUT_PARAM, "Invalid plugin context.");
    }

    return ret;
}

irods::error openid_auth_client_start(
    irods::plugin_context& _ctx,
    rcComm_t*              _comm,
    const char*            _inst_name)
{
    irods::error result = SUCCESS();
    irods::error ret;

    ret = _ctx.valid<irods::openid_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context.") ).ok() )
    {
        if ( ( result = ASSERT_ERROR( _comm != NULL, SYS_INVALID_INPUT_PARAM, "Null rcComm_t pointer." ) ).ok() )
        {
            irods::openid_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::openid_auth_object>(_ctx.fco());

            // set the user name from the conn
            ptr->user_name( _comm->proxyUser.userName );
            
            // se the zone name from the conn
            ptr->zone_name( _comm->proxyUser.rodsZone );

            // set the socket from the conn
            //ptr->sock( _comm->sock );
        }
    }

    return result;
}


// Auth request call on client side
// Sends auth request to server
irods::error openid_auth_client_request(
    irods::plugin_context& _ctx,
    rcComm_t*              _comm )
{
    irods::error ret;
    
    // validate incoming parameters
    if ( !_ctx.valid<irods::openid_auth_object>().ok() )
    {
        return ERROR( SYS_INVALID_INPUT_PARAM, "Invalid plugin context." );
    }
    else if ( !_comm )
    {
        return ERROR( SYS_INVALID_INPUT_PARAM, "null comm ptr" );
    }

    // get the auth object
    irods::openid_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::openid_auth_object>( _ctx.fco() );

    // get context string
    std::string context = ptr->context();
    if ( context.empty() )
    {
        return ERROR( SYS_INVALID_INPUT_PARAM, "Empty plugin context string" );
    }
    
    // expand the context string
    irods::kvp_map_t ctx_map;
    ret = irods::parse_escaped_kvp_string( context, ctx_map );
    if ( !ret.ok() )
    {
        return PASS( ret );
    }
    
    ctx_map[irods::AUTH_USER_KEY] = ptr->user_name();
    std::string ctx_str = irods::escaped_kvp_string( ctx_map );

    if ( context.size() > MAX_NAME_LEN )
    {
        return ERROR( -1, "context string > max name len" );
    }

    // copy context to req in
    authPluginReqInp_t req_in;
    strncpy( req_in.context_, ctx_str.c_str(), ctx_str.size() + 1 );
    
    // copy auth scheme to the req in struct
    // TODO refactor
    strncpy( req_in.auth_scheme_, "openid", strlen("openid") );

    // warm up ssl if not in use (pam does this but not kerberos or gsi)
    bool using_ssl = ( irods::CS_NEG_USE_SSL == _comm->negotiation_results );
    if ( !using_ssl )
    {
        int err = sslStart( _comm );
        if ( err )
        {
            return ERROR( err, "failed to enable ssl" );
        }
    }

    authPluginReqOut_t *req_out = 0;
    int status = rcAuthPluginRequest( _comm, &req_in, &req_out );

    // shut down ssl if it was not already in use
    if ( !using_ssl )
    {
        sslEnd( _comm );
    }

    // handle errors and exit
    if ( status < 0 )
    {
        return ERROR( status, "call to rcAuthRequest failed." );
    }
    else
    {
        // copy over resulting openid session token
        // and cache the result in our auth object
        ptr->request_result( req_out->result_ );
        obfSavePw( 0, 0, 0, req_out->result_ );
        free( req_out );
        return SUCCESS();
    }
}

irods::error openid_auth_client_response(
    irods::plugin_context& _ctx,
    rcComm_t*              _comm )
{
    irods::error result = SUCCESS();
    irods::error ret;

    // validate incoming parameters
    ret = _ctx.valid<irods::openid_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context." ) ).ok() ) {
        if ( ( result = ASSERT_ERROR( _comm, SYS_INVALID_INPUT_PARAM, "Null comm pointer." ) ).ok() ) {

            // =-=-=-=-=-=-=-
            // get the auth object
            irods::openid_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::openid_auth_object>( _ctx.fco() );

            irods::kvp_map_t kvp;
            kvp[irods::AUTH_SCHEME_KEY] = "openid"; //TODO refactor
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

            authResponseInp_t auth_response;
            auth_response.response = response;
            auth_response.username = username;
            int status = rcAuthResponse( _comm, &auth_response );
            result = ASSERT_ERROR( status >= 0, status, "Call to rcAuthResponseFailed." );
        }
    }

    return result; 
}

#ifdef RODS_SERVER
irods::error openid_auth_agent_start(
    irods::plugin_context& _ctx,
    const char*            _inst_name)
{
    irods::error result = SUCCESS();
    irods::error ret;

    ret = _ctx.valid<irods::openid_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context" ) ).ok() )
    {
        irods::openid_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::openid_auth_object>( _ctx.fco() );
        
        std::string provider_discovery_url = irods::get_server_property<std::string>("openid_provider_discovery_url");
        std::string client_id = irods::get_server_property<std::string>("openid_client_id");
        std::string client_secret = irods::get_server_property<std::string>("openid_client_secret");
        std::string redirect_uri = irods::get_server_property<std::string>("openid_redirect_uri");
        std::string authorization_endpoint;
        std::string token_endpoint;

        if ( !get_provider_metadata_field( provider_discovery_url, "authorization_endpoint", authorization_endpoint )
            || ! get_provider_metadata_field( provider_discovery_url, "token_endpoint", token_endpoint) )
        {
            std::cout << "Provider discovery metadata missing fields" << std::endl;
            return ERROR(-1, "Provider discovery metadata missing fields");
        }

        std::string authorize_url_fmt = "%s?response_type=%s&scope=%s&client_id=%s&redirect_uri=%s";
        boost::format fmt(authorize_url_fmt);
        fmt % authorization_endpoint
            % "code"
            % "openid"
            % client_id
            % redirect_uri; 
            
        std::cout << "Waiting for OpenID provider authorization...\n" << authorize_url_fmt << std::endl;

        std::string *request_message = accept_request(8080);
        std::map<std::string,std::string> *param_map = get_params(*request_message);
        
        // check for code in callback
        if ( param_map->find("code") != param_map->end() )
        {
            std::string authorization_code = param_map->at("code");
            std::string *access_token_response = get_access_token(
                                                token_endpoint,
                                                authorization_code,
                                                client_id,
                                                client_secret,
                                                redirect_uri);
            std::cout << *access_token_response << std::endl;
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
                std::cout << "id_token: " << id_token << std::endl;
                // TODO base64 decode and validate fields 
                // https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                std::cout << "access_token: " << access_token << std::endl;
                std::cout << "expires_in: " << expires_in << std::endl;
            }
            delete access_token_response;

        }
        else
        {
            return ERROR(-1, "Redirect callback missing required params");
        }
    } // end plugin context check
    return SUCCESS();
}

irods::error openid_auth_agent_request(
    irods::plugin_context& _ctx ) {
    return SUCCESS();
}

irods::error openid_auth_agent_response(
    irods::plugin_context& _ctx,
    authResponseInp_t*     _resp ) {
    return SUCCESS();
}

irods::error openid_auth_agent_verify(
    irods::plugin_context& _ctx,
    const char*            _challenge,
    const char*            _user_name,
    const char*            _response ) {
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
