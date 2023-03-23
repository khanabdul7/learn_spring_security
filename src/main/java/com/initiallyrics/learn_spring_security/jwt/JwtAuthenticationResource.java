package com.initiallyrics.learn_spring_security.jwt;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/*
 *NOTE: How Authentication Works : https://www.udemy.com/course/spring-boot-and-spring-framework-tutorial-for-beginners/learn/lecture/35017628#content 
 */

@RestController
public class JwtAuthenticationResource {

	private JwtEncoder jwtEncoder;
	
	public JwtAuthenticationResource(JwtEncoder jwtEncoder) {
		this.jwtEncoder = jwtEncoder;
	}
	
	//below class will be used to send JWT token back
	@PostMapping("/authenticate")
	public JwtResponse authentication(Authentication authentication) {   //AuthenticationManager is an interface(which has a method Authentication), which receives authentication obj(which includes credentials only) if the authentication is successful then principal(details about user) and authorities(roles) also added along credentials
		return new JwtResponse(createToken(authentication));
	}
	
	private String createToken(Authentication authentication) {  //creating token
		var claims = JwtClaimsSet.builder()
								.issuer("self")
								.issuedAt(Instant.now())
								.expiresAt(Instant.now().plusSeconds(60 * 30))  // setting expire time 30 mins.
								.subject(authentication.getName())
								.claim("scope", createScope(authentication))
								.build();
		
		return jwtEncoder.encode(JwtEncoderParameters.from(claims))
						.getTokenValue();
	}
	
	private String createScope(Authentication authentication) {  // this method will get all roles of a user, using getAuthorities
		return authentication.getAuthorities().stream()
			.map(a -> a.getAuthority())
			.collect(Collectors.joining(" "));			
	}
}

record JwtResponse(String token) {}