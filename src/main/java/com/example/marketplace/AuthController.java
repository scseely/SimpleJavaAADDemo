package com.example.marketplace;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@RestController
@Slf4j
public class AuthController {
    private final AuthHelper authHelper;

    public AuthController(AuthHelper helper){
        this.authHelper = helper;
    }

    @PostMapping(value = "/aad", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public void authenticate(HttpServletRequest servletRequest,
                             HttpServletResponse servletResponse,
                             @RequestParam Map<String, String> formData) throws Throwable {
        this.authHelper.authenticate(servletRequest, formData);
        servletResponse.sendRedirect("/");
    }
}
