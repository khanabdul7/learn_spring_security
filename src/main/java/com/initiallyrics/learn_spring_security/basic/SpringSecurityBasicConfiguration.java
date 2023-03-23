package com.initiallyrics.learn_spring_security.basic;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


//@Configuration
public class SpringSecurityBasicConfiguration {

	// defining our own chain of filters
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests(auth -> {  //authenticate all reqs that are coming.
			auth.anyRequest().authenticated();
		});

		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));  //making session as STATELESS.

		// http.formLogin();   //disabling form login
		http.httpBasic();      // only allows basic authentication.
		http.csrf().disable();   //disabling CSRF bcos server is stateless.
		http.headers().frameOptions().sameOrigin(); //allowing frameOptions from  same origin.
		return http.build();
	}
	
	// below class is used to generate DDL for storing our users in DB
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder()
					.setType(EmbeddedDatabaseType.H2) //type of DB
					.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION) //giving the DDL script location.(this script is by default available in JdbcDaoImpl class.)
					.build();
	}
	
	// below service is used to create users in DB, add their credentials and Roles.
	@Bean
	public UserDetailsService userDetailsService(DataSource dataSource) {
		
		var user = User.withUsername("abdul")
						//.password("{noop}dummy") storing password without any hashing algo
						.password("dummy")
						.passwordEncoder(input -> bcryptPasswordEncoder().encode(input))// using bcryptEncoder(Hashing algo)
						.roles("USER")
						.build();
					
		var admin = User.withUsername("admin")
//				.password("{noop}admin") storing password without any hashing algo
				.password("admin")
				.passwordEncoder(input -> bcryptPasswordEncoder().encode(input))
				.roles("ADMIN")
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
}
