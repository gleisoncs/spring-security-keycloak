package com.ailos.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.net.URI;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {


    @Value("${spring.security.oauth2.client.registration.cognito.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.cognito.logout-uri}")
    private String logoutUrl;

    @Value("${client.post-logout-uri}")
    private String postLogoutUri;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf()
//            .and()
//            .authorizeRequests(authz -> authz.mvcMatchers("/")
//                .permitAll()
//                .anyRequest()
//                .authenticated())
//            .oauth2Login().loginPage("/login")
//            .and()
//                .logout()
//                .logoutSuccessHandler(new CognitoOidcLogoutSuccessHandler(logoutUrl, clientId, postLogoutUri));

        http.authorizeRequests()
                .antMatchers("/login","/css/*", "/images/*")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .oauth2Login()
                .loginPage("/login")
                .and()
                .logout().logoutUrl("/logout")
                .logoutSuccessHandler(new CognitoOidcLogoutSuccessHandler(logoutUrl, clientId, postLogoutUri));
    }


    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {

        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(
                this.clientRegistrationRepository);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(URI.create(postLogoutUri));
        return oidcLogoutSuccessHandler;
    }
}