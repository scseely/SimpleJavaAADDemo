package com.example.marketplace;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;

@Component
public class AuthHelper {
    AadConfiguration aadConfig;

    public AuthHelper(AadConfiguration config){
        aadConfig = config;
    }

    static final String PRINCIPAL_SESSION_NAME = "principal";
    static final String NONCE_SESSION_NAME = "nonce";
    static final String AAD_ID_TOKEN_NAME = "aad.id_token";
    static final String AAD_CODE_NAME = "aad.code";
    static final String AAD_SESSION_STATE_NAME = "aad.session_state";
    static final String FAILED_TO_VALIDATE_MESSAGE = "Failed to validate data received from Authorization service - ";
    static final Charset utf8 = Charset.forName(StandardCharsets.UTF_8.name());

    public boolean isAuthenticated(HttpServletRequest request){
        HttpSession session = request.getSession();
        Object principal = session.getAttribute(PRINCIPAL_SESSION_NAME);
        return null != principal;
    }

    public String getAadUri(HttpServletRequest request) throws URISyntaxException {
        HttpSession session = request.getSession();
        String nonce = UUID.randomUUID().toString();
        session.setAttribute(NONCE_SESSION_NAME, nonce);
        URI requestHost = new URI(request.getRequestURL().toString());
        String redirectUri = String.format("%s://%s:%s%s",
                requestHost.getScheme(),
                requestHost.getHost(),
                requestHost.getPort(),
                aadConfig.getRedirectUriSignin());
        String redirectUriEncoded = URLEncoder.encode(redirectUri, utf8);
        return String.format(
                "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code+id_token&redirect_uri=%s&client_id=%s&scope=openid+profile+email&response_mode=form_post&nonce=%s",
                redirectUriEncoded,
                aadConfig.getClientId(),
                nonce);
    }

    public void authenticate(HttpServletRequest servletRequest, Map<String, String> formData) throws Throwable{
        String code = formData.get("code");
        String idToken = formData.get("id_token");
        String sessionState = formData.get("session_state");
        HttpSession session = servletRequest.getSession();
        addAuthToSession(session, code, idToken, sessionState);

        Map<String, List<String>> params = toMapStringListString(formData);
        URI currentUri = new URI(servletRequest.getRequestURI());
        AuthenticationResponse authResponse = AuthenticationResponseParser.parse(currentUri, params);
        if (isAuthenticationSuccessful(authResponse)){
            JWT jwt = JWTParser.parse(idToken);

            AuthenticationSuccessResponse oidcResponse = (AuthenticationSuccessResponse) authResponse;

            // validate that Open ID Connect Auth Response matches Code Flow (contains only requested artifacts)
            validateAuthRespMatchesAuthCodeFlow(oidcResponse);

            // validate nonce to prevent reply attacks
            validateNonce(session, getNonceClaimValue(jwt));

            setSessionPrincipal(session, jwt);
        }else {
            AuthenticationErrorResponse oidcResponse = (AuthenticationErrorResponse) authResponse;
            throw new Exception(String.format("Request for auth code failed: %s - %s",
                    oidcResponse.getErrorObject().getCode(),
                    oidcResponse.getErrorObject().getDescription()));
        }
    }

    private void setSessionPrincipal(HttpSession session, JWT jwt) {
        session.setAttribute(PRINCIPAL_SESSION_NAME, jwt.serialize());
    }

    public JWT getSessionPrincipal(HttpSession session) throws ParseException {
        String rawJwt = (String) session.getAttribute(PRINCIPAL_SESSION_NAME);
        return JWTParser.parse(rawJwt);
    }

    private String getNonceClaimValue(JWT jwt) throws ParseException {
        return (String) jwt.getJWTClaimsSet().getClaim(NONCE_SESSION_NAME);
    }

    private static boolean isAuthenticationSuccessful(AuthenticationResponse authResponse) {
        return authResponse instanceof AuthenticationSuccessResponse;
    }

    private static Map<String, List<String>> toMapStringListString(Map<String, String> formData){
        Map<String, List<String>> params = new HashMap<>(formData.size());
        for (String key : formData.keySet()){
            params.put(key, Collections.singletonList(formData.get(key)));
        }
        return params;
    }

    private void validateAuthRespMatchesAuthCodeFlow(AuthenticationSuccessResponse oidcResponse) throws Exception {
        JWT idToken = oidcResponse.getIDToken();
        AccessToken accessToken = oidcResponse.getAccessToken();
        AuthorizationCode authorizationCode = oidcResponse.getAuthorizationCode();
        if (idToken == null || accessToken != null || authorizationCode == null) {
            throw new Exception(String.format("%s%s", FAILED_TO_VALIDATE_MESSAGE, "unexpected set of artifacts received"));
        }
    }

    private void validateNonce(HttpSession session, String nonce) throws Exception {
        String sessionNonce = (String) session.getAttribute(NONCE_SESSION_NAME);
        if (StringUtils.isEmpty(nonce) || !nonce.equals(sessionNonce)) {
            throw new Exception(String.format("%s%s", FAILED_TO_VALIDATE_MESSAGE, "could not validate nonce"));
        }
    }

    private static void addAuthToSession(HttpSession session, String code, String idToken, String sessionState){
        session.setAttribute(AAD_CODE_NAME, code);
        session.setAttribute(AAD_ID_TOKEN_NAME, idToken);
        session.setAttribute(AAD_SESSION_STATE_NAME, sessionState);
    }
}
