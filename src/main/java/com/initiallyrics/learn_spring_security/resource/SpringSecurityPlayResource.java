package com.initiallyrics.learn_spring_security.resource;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.HttpRequestHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class SpringSecurityPlayResource {

	//we are retrieving a CSRF token 
	@GetMapping("csrf")
	public CsrfToken retrieveCsrfToken(HttpServletRequest http) {
		return (CsrfToken) http.getAttribute("_csrf");
	}
}
