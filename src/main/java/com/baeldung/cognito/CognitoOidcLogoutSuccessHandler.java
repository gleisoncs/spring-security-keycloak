package com.baeldung.cognito;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;

public class CognitoOidcLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private final String logoutUrl;
    private final String clientId;
    private final String postLogoutUri;

    public CognitoOidcLogoutSuccessHandler(String logoutUrl, String clientId, String postLogoutUri) {
        this.logoutUrl = logoutUrl;
        this.clientId = clientId;
        this.postLogoutUri = postLogoutUri;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {

        UriComponents baseUrl = UriComponentsBuilder
                .fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
                .replacePath(request.getContextPath())
                .replaceQuery(null)
                .fragment(null)
                .build();

        return UriComponentsBuilder
                .fromUri(URI.create(logoutUrl))
                .queryParam("client_id", clientId)
                .queryParam("logout_uri", baseUrl)
                .queryParam("redirect_uri", postLogoutUri)
                .queryParam("response_type", "code")
                .encode(StandardCharsets.UTF_8)
                .build()
                .toUriString();
    }
}
