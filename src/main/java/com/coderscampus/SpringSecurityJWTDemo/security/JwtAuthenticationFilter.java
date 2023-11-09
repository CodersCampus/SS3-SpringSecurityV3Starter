package com.coderscampus.SpringSecurityJWTDemo.security;

import java.io.IOException;

import org.springframework.util.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.coderscampus.SpringSecurityJWTDemo.service.UserService;
import com.coderscampus.SpringSecurityJWTDemo.service.UserServiceImpl;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtServiceImpl jwtService;
    private final UserServiceImpl userService;
    
    public JwtAuthenticationFilter(JwtServiceImpl jwtService, UserServiceImpl userService) {
        super();
        this.jwtService = jwtService;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        Cookie accessTokenCookie = null;
        Cookie refreshTokenCookie = null;
        
        if (request.getCookies() != null) {
        	for (Cookie cookie : request.getCookies()) {
        		if (cookie.getName().equals("accessToken")) {
        			accessTokenCookie = cookie;
        		} else if (cookie.getName().equals("refreshToken")) {
        			refreshTokenCookie = cookie;
        		}
        	}
        }
        
//        if (StringUtils.isEmpty(authHeader) || !StringUtils.startsWith(authHeader, "Bearer ")) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//        jwt = authHeader.substring(7);
//        userEmail = jwtService.extractUserName(jwt);
//        if (StringUtils.isNotEmpty(userEmail)
//        		&& SecurityContextHolder.getContext().getAuthentication() == null) {
//        	UserDetails userDetails = userService.userDetailsService()
//        			.loadUserByUsername(userEmail);
//        	if (jwtService.isTokenValid(jwt, userDetails)) {
//        		SecurityContext context = SecurityContextHolder.createEmptyContext();
//        		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//        				userDetails, null, userDetails.getAuthorities());
//        		authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//        		context.setAuthentication(authToken);
//        		SecurityContextHolder.setContext(context);
//        	}
//        }
//        filterChain.doFilter(request, response);
        
        if (accessTokenCookie != null) {
        	try {
				String token = accessTokenCookie.getValue();
				String subject = jwtService.extractUserName(token);
				
				Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
				if (StringUtils.hasText(subject) && authentication == null) {
					UserDetails userDetails = userService.userDetailsService().loadUserByUsername(subject);
					
					if (jwtService.isTokenValid(token, userDetails)) {
						SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
						UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken (userDetails,
								userDetails.getPassword(),
								userDetails.getAuthorities());
						securityContext.setAuthentication(authToken);
						SecurityContextHolder.setContext(securityContext);
					}
				}
			} catch (ExpiredJwtException e) {
				// TODO Auto-generated catch block
//				e.printStackTrace();
			}
        }
        filterChain.doFilter(request, response);
    }
}