package br.com.cinbesa.ws;

import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.request.AbstractOAuthTokenRequest;
import org.apache.oltu.oauth2.as.request.OAuthTokenRequest;
import org.apache.oltu.oauth2.as.request.OAuthUnauthenticatedTokenRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * Created by gilson on 20/01/16.
 */
@Path("/token")
public class TokenRest {

    public static final String CLIENTE_INVALIDO = "Cliente inválido";
    public static final String FLUXO_NAO_SUPORTADO = "Fluxo de autorização não suportado";
    public static final String TOKEN_TTL = "3600";

    @POST
    @Path("/")
    @Produces("application/json")
    @Consumes("application/x-www-form-urlencoded")
    public Response post(@Context HttpServletRequest request) throws OAuthSystemException {
        try {
            AbstractOAuthTokenRequest oauthRequest = new OAuthImplictResquest(request);
            OAuthIssuer oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());

            if (oauthRequest.getParam(OAuth.OAUTH_GRANT_TYPE).equals(GrantType.IMPLICIT.toString())) {
                if (!clienteValido(oauthRequest)) {
                    return respostaClienteInvalido();
                }

                return respostaComToken(oauthIssuerImpl);
            } else if (oauthRequest.getParam(OAuth.OAUTH_GRANT_TYPE).equals(GrantType.REFRESH_TOKEN.toString())) {
                String refreshToken = oauthRequest.getRefreshToken();
                if (!refreshTokenValido(refreshToken)) {
                    return respostaClienteInvalido();
                }

                return respostaComToken(oauthIssuerImpl);
            } else {
                return respostaTipoAutorizacaoNaoSuportado();
            }
        } catch (OAuthProblemException e) {
            return repostaErroInterno(e);
        }
    }

    private boolean refreshTokenValido(String refreshToken) {
        return true;
    }

    private Response repostaErroInterno(OAuthProblemException e) throws OAuthSystemException {
        OAuthResponse res = OAuthASResponse
                .errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)
                .error(e)
                .buildJSONMessage();

        return Response.status(res.getResponseStatus()).entity(res.getBody()).build();
    }

    private Response respostaComToken(OAuthIssuer oauthIssuerImpl) throws OAuthSystemException {
        final String accessToken = oauthIssuerImpl.accessToken();
        final String refreshToken = oauthIssuerImpl.refreshToken();
        //Guardar os tokens para validar no Rest Interceptor (Usar Cache não banco). Apache Commons JCS (Java Caching System)

        OAuthResponse response = OAuthASResponse
                .tokenResponse(HttpServletResponse.SC_OK)
                .setAccessToken(accessToken)
                .setRefreshToken(refreshToken)
                .setExpiresIn(TOKEN_TTL)
                .setTokenType("Bearer")
                .buildJSONMessage();

        return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
    }

    private Response respostaClienteInvalido() throws OAuthSystemException {
        OAuthResponse response = OAuthASResponse
                .errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                .setError(OAuthError.TokenResponse.INVALID_CLIENT)
                .setErrorDescription(CLIENTE_INVALIDO)
                .buildJSONMessage();

        return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
    }

    private Response respostaTipoAutorizacaoNaoSuportado() throws OAuthSystemException {
        OAuthResponse response = OAuthASResponse
                .errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                .setError(OAuthError.TokenResponse.INVALID_GRANT)
                .setErrorDescription(FLUXO_NAO_SUPORTADO)
                .buildJSONMessage();

        return Response.status(response.getResponseStatus()).entity(response.getBody()).build();
    }

    private boolean clienteValido(AbstractOAuthTokenRequest oauthRequest) {
        //Consultar no banco
        return oauthRequest.getClientId() != null;
    }
}