package com.coderscampus.SpringSecurityJWTDemo.security;

import com.coderscampus.SpringSecurityJWTDemo.domain.RefreshToken;
import com.coderscampus.SpringSecurityJWTDemo.domain.Role;

import java.util.HashMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import com.coderscampus.SpringSecurityJWTDemo.service.RefreshTokenService;
import com.coderscampus.SpringSecurityJWTDemo.service.UserService;
import com.coderscampus.SpringSecurityJWTDemo.utils.CookieUtils;
import com.coderscampus.SpringSecurityJWTDemo.domain.User;

import io.jsonwebtoken.io.IOException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
	private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserDetailsService userDetailsService; 
	@Autowired
	private RefreshTokenService refreshTokenService;
	@Autowired
	private JwtServiceImpl jwtServiceImpl;

	public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,  UserDetailsService userDetailsService) {
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
		this.userDetailsService = userDetailsService;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.csrf(AbstractHttpConfigurer::disable)
//        .authorizeHttpRequests(request -> request.requestMatchers("**").permitAll().anyRequest().authenticated())
				.authorizeHttpRequests(request -> {
					request
//                                		.requestMatchers("/api/v1/auth/**").permitAll()
						.requestMatchers("/admin/**").hasRole(Role.ADMIN.name())
						.requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll()
						.requestMatchers("/signup").permitAll()
						.requestMatchers("/products").authenticated()
						.requestMatchers("/register").permitAll()
						.anyRequest().authenticated();
				})
				.headers(header -> header.frameOptions(frameOption -> frameOption.disable()))
//				.sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authenticationProvider(authenticationProvider())
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
				.formLogin(this::configureFormLogin);
//                .formLogin(login -> {
//		        	login.loginPage("/register");
//		        	login.successForwardUrl("/success");
//		        	login.failureForwardUrl("/error");
//		        	login.permitAll();
//		        });
		return http.build();
	}

	private void configureFormLogin(FormLoginConfigurer<HttpSecurity> login) {
		login.loginPage("/login") // Listens to POST /viewlogin and sends it to spring sec( user details service
									// -> loadUserByUsername )
		        .usernameParameter("email")
		        .successHandler(this::onAuthenticationSuccess) // Set the custom success handler
				.failureHandler(this::onAuthenticationFailure) // Set the custom failure handler
				.permitAll();
	}

	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {


		// Log user details:
		User user = (User) authentication.getPrincipal(); // Cast to your User domain object
		System.out.println("Authentication successful for user: " + user.getUsername());
		System.out.println("Authorities: " + user.getAuthorities());
		System.out.println("Authentication successful for user: " + user.getUsername());

		// Hard code redirect site:
		String redirectUrl = "/products";
		System.out.println("Redirecting to: " + redirectUrl);

		// Perform the redirect
		try {
			response.sendRedirect(redirectUrl);
		} catch (java.io.IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		// Get the username and password from the login request
		String email = request.getParameter("email");
		String password = request.getParameter("password");

		// Log authentication failure details
		System.out.println("Authentication failed for user: " + email);
		System.out.println("Authentication failure exception: " + exception.getMessage());

		// Log the provided credentials and expected credentials
		System.out.println("Provided email: " + email);
		System.out.println("Provided Password: " + password);

		try {
			response.sendRedirect("/login-error");
		} catch (java.io.IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	

	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}
}