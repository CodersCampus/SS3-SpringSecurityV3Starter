package com.coderscampus.SpringSecurityJWTDemo.security;

import java.io.IOException;

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
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.coderscampus.SpringSecurityJWTDemo.domain.RefreshToken;
import com.coderscampus.SpringSecurityJWTDemo.domain.Role;
import com.coderscampus.SpringSecurityJWTDemo.domain.User;
import com.coderscampus.SpringSecurityJWTDemo.service.RefreshTokenService;
import com.coderscampus.SpringSecurityJWTDemo.service.UserService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserService userService;
    
    @Autowired
    private JwtServiceImpl jwtService;
    
    @Autowired
    private RefreshTokenService refreshTokenService;
    
    public SecurityConfig (JwtAuthenticationFilter jwtAuthenticationFilter, UserService userService) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userService = userService;
    }
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
//        .authorizeHttpRequests(request -> request.requestMatchers("**").permitAll().anyRequest().authenticated())
                .authorizeHttpRequests(request ->
                                request
//                                		.requestMatchers("/api/v1/auth/**").permitAll()
                                        .requestMatchers("/admin/**").hasRole(Role.ADMIN.name())
                                        .requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll()
                                        .requestMatchers("/products").authenticated()
//                                        	.requestMatchers("/signin").permitAll()
                                        	.requestMatchers("/register").permitAll()
                                        	.anyRequest().permitAll()
                        )
                .headers(header -> header.frameOptions(frameOption -> frameOption.disable()))
                .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider()).addFilterBefore(
                        jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin(login -> {
		        	login.loginPage("/signin");
//		        	login.successForwardUrl("/success");
//		        	login.failureUrl("/failure"); // this can be linked to a failure message on the failure template
//		        	login.failureForwardUrl("/error");
		        	login.successHandler(new AuthenticationSuccessHandler() {
						
						@Override
						public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
								Authentication authentication) throws IOException, ServletException {
							
							User user = (User) authentication.getPrincipal();
					    	String accessToken = jwtService.generateToken(user);
					    	RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());
							
					    	Cookie accessCookie = new Cookie("accessToken", accessToken);
					    	Cookie refreshCookie = new Cookie("refreshToken", refreshToken.getToken());
					    	
					    	response.addCookie(accessCookie);
					    	response.addCookie(refreshCookie);
					    	response.sendRedirect("/products");
						}
					});
		        	login.permitAll();
		        });
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userService.userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }
}