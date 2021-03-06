package com.example.marketplace;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.ParseException;

@RestController
public class LandingPageController {

    AuthHelper authHelper;

    @Autowired
    public LandingPageController(AuthHelper helper) {
        authHelper = helper;
    }

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public ModelAndView index(HttpServletRequest request, HttpServletResponse response) throws ParseException {
        ModelAndView mav = new ModelAndView("index");
        JWT jwt = authHelper.getSessionPrincipal(request.getSession());
        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        mav.addObject("fullName", claims.getStringClaim("name"));
        mav.addObject("emailAddress", claims.getStringClaim("email"));
        mav.addObject("tenantId", claims.getStringClaim("tid"));

        return mav;
    }
}