package com.initiallyrics.learn_spring_security.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class SpringSecurityJwtConfiguration {

	// defining our own chain of filters
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests(auth -> { // authenticate all reqs that are coming.
			auth.anyRequest().authenticated();
		});

		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // making
																											// session
																											// as
																											// STATELESS.

		// http.formLogin(); //disabling form login
		http.httpBasic(); // only allows basic authentication.
		http.csrf().disable(); // disabling CSRF bcos server is stateless.
		http.headers().frameOptions().sameOrigin(); // allowing frameOptions from same origin.
		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt); // configuring server for accepting JWT token
																		// and decode it.
		return http.build();
	}

	// below class is used to generate DDL for storing our users in DB
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2) // type of DB
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION) // giving the DDL script location.(this script
																			// is by default available in JdbcDaoImpl
																			// class.)
				.build();
	}

	// below service is used to create users in DB, add their credentials and Roles.
	@Bean
	public UserDetailsService userDetailsService(DataSource dataSource) {

		var user = User.withUsername("abdul")
				// .password("{noop}dummy") storing password without any hashing algo
				.password("dummy").passwordEncoder(input -> bcryptPasswordEncoder().encode(input))// using
																									// bcryptEncoder(Hashing
																									// algo)
				.roles("USER").build();

		var admin = User.withUsername("admin")
//				.password("{noop}admin") storing password without any hashing algo
				.password("admin").passwordEncoder(input -> bcryptPasswordEncoder().encode(input)).roles("ADMIN")
				.build();

		var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);
		return jdbcUserDetailsManager;
	}

	@Bean
	public BCryptPasswordEncoder bcryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/*
	 * In Asymmetric cryptography, we create key pairs (public key and private key).
	 * if message is encrypted using public key it can only be decrypt its
	 * corresponding private key and vice-versa.
	 * 
	 * 
	 * Example: suppose there are 2 persons (A & B). according to Asymmetric
	 * cryptography they both generate their key pairs.(i.e both A & B generate
	 * their public and private keys). after generating their key pairs they share
	 * our public keys to each other. (A's public key will send to B and B's public
	 * key will send to A). Now since they both have each others public keys, they
	 * can encrypt the message with other person's public key so that other person
	 * can decrypt using his private key. NOTE: this can be done in opposite way
	 * also, i.e: we can encrypt using our own private key so that other person can
	 * dcrypt using our shared public key. (that we shared earlier).
	 * 
	 * 
	 * for visual representation see this link :
	 * https://www.youtube.com/watch?v=AQDCe585Lnc
	 * 
	 * NOTE: 1. Create JWT token. (needs Encoding(accepts user credentials, payload, RSA key pair), also create a resource with '/authenticate' endpoint.)
	 * 		 2. Send JWT as a part of request header.(authorization header, bearer token)
	 * 		 3. JWT is verified. (needs decoding, RSA key pair)
	 */

	@Bean // generating key pair using RSA algo
	public KeyPair keyPair() {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048); // more length more security
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	@Bean //creating an RSA key obj, using private key here 
	public RSAKey rsaKey(KeyPair keyPair) {

		return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).privateKey(keyPair.getPrivate())
				.keyID(UUID.randomUUID().toString()).build();
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		var jwkSet = new JWKSet(rsaKey);

		return (jwkSelector, context) -> jwkSelector.select(jwkSet);

	}

	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException { // decoding using public key
		return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();

	}

	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {  //encoder, will encode the Jwt token
		return new NimbusJwtEncoder(jwkSource);
	}
}
