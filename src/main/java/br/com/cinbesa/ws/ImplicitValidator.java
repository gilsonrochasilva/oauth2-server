package br.com.cinbesa.ws;

import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by gilson on 20/04/16.
 */
public class ImplicitValidator extends AbstractValidator<HttpServletRequest> {

    public ImplicitValidator() {
        this.requiredParams.add("grant_type");
        this.requiredParams.add("client_id");
        this.enforceClientAuthentication = false;
    }
}