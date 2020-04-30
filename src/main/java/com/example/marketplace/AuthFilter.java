package com.example.marketplace;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
@Slf4j
public class AuthFilter implements Filter {

    private final List<String> excludedUrls = Arrays.asList("/aad", "favicon.ico");

    AuthHelper authHelper;

    public AuthFilter(AuthHelper helper){
        authHelper = helper;
    }

    @SneakyThrows
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        if (servletRequest instanceof HttpServletRequest) {
            HttpServletRequest request = (HttpServletRequest) servletRequest;
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            String path = request.getServletPath();
            log.info(String.format("Request for %s", path));
            log.debug("This is a test debug");
            if (excludedUrls.contains(path)) {
                filterChain.doFilter(servletRequest, servletResponse);
            } else if (!authHelper.isAuthenticated(request)) {
                String redirectUri = authHelper.getAadUri(request);

                response.sendRedirect(redirectUri);
            } else {
                filterChain.doFilter(servletRequest, servletResponse);
            }
        }
    }
}
