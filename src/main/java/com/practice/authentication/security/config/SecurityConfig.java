package com.practice.authentication.security.config;

import com.practice.authentication.security.service.OAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Đường dẫn không yêu cầu đăng nhập
    private static final String[] PUBLIC_MATCHERS = {
            "/register/**", "/login/**", "/css/**", "/js/**"
    };

    // Đường dẫn đến trang đăng nhập
    private static final String LOGIN_PAGE = "/login";

    // Trang đích sau khi đăng nhập thành công
    private static final String LOGIN_SUCCESS_URL = "/home";

    // Đường dẫn logout
    private static final String LOGOUT_URL = "/logout";

    // Trang đích sau khi logout
    private static final String LOGOUT_SUCCESS_URL = "/login?logout";

    // Khóa bí mật cho remember-me
    private static final String REMEMBER_ME_KEY = "secret key asfkjakejlcs";

    // Thời gian remember-me (s)
    private static final int REMEMBER_ME_VALIDITY = 36;

    @Autowired
    private OAuth2UserService oAuth2UserService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests()
                .requestMatchers(PUBLIC_MATCHERS).permitAll()
                .anyRequest().authenticated()
            .and().formLogin()
                .loginPage(LOGIN_PAGE)
                .failureHandler(loginFailureHandler())
                .defaultSuccessUrl(LOGIN_SUCCESS_URL, true).permitAll()
            .and().logout()
                .logoutRequestMatcher(new AntPathRequestMatcher(LOGOUT_URL))
                .logoutSuccessUrl(LOGOUT_SUCCESS_URL).permitAll()
            .and().rememberMe()
                .key(REMEMBER_ME_KEY)
                .tokenValiditySeconds(REMEMBER_ME_VALIDITY)
            .and().oauth2Login()
                .loginPage(LOGIN_PAGE)
                .failureHandler(oauth2FailureHandler())
                .defaultSuccessUrl(LOGIN_SUCCESS_URL, true)
                .userInfoEndpoint().userService(oAuth2UserService);

        return http.build();
    }

    @Bean
    public AuthenticationFailureHandler loginFailureHandler() {
        return (request, response, exception) -> {
            String error;
            if (exception instanceof BadCredentialsException
                    || exception instanceof UsernameNotFoundException) {
                error = "incorrect_username_or_password";
            } else {
                error = "unknown_error";
            }
            response.sendRedirect("/login?" + error);
        };
    }

    @Bean
    public AuthenticationFailureHandler oauth2FailureHandler() {
        return (request, response, exception) -> {
            if (exception instanceof OAuth2AuthenticationException authEx) {
                String error = authEx.getError().getErrorCode();
                if (error.equals("account_already_linked")) {
                    response.sendRedirect("/home?account_already_linked");
                }
            } else {
                response.sendRedirect("/login?error");
            }
        };
    }

}