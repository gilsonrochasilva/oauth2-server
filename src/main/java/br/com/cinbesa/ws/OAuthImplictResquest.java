package br.com.cinbesa.ws;

import org.apache.oltu.oauth2.as.request.AbstractOAuthTokenRequest;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.validators.OAuthValidator;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by gilson on 20/04/16.
 */
public class OAuthImplictResquest extends AbstractOAuthTokenRequest {
    public OAuthImplictResquest(HttpServletRequest request) throws OAuthSystemException, OAuthProblemException {
        super(request);
    }

    protected OAuthValidator<HttpServletRequest> initValidator() throws OAuthProblemException, OAuthSystemException {
        this.validators.put(GrantType.IMPLICIT.toString(), ImplicitValidator.class);
        this.validators.put(GrantType.REFRESH_TOKEN.toString(), ImplicitValidator.class);
        return super.initValidator();
    }
}