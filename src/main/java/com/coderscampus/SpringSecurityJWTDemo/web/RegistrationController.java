package com.coderscampus.SpringSecurityJWTDemo.web;

import java.util.HashMap;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import com.coderscampus.SpringSecurityJWTDemo.dao.request.SignUpRequest;
import com.coderscampus.SpringSecurityJWTDemo.dao.response.JwtAuthenticationResponse;
import com.coderscampus.SpringSecurityJWTDemo.domain.RefreshToken;
import com.coderscampus.SpringSecurityJWTDemo.domain.User;
import com.coderscampus.SpringSecurityJWTDemo.security.AuthenticationService;
import com.coderscampus.SpringSecurityJWTDemo.security.AuthenticationServiceImpl;
import com.coderscampus.SpringSecurityJWTDemo.security.JwtServiceImpl;
import com.coderscampus.SpringSecurityJWTDemo.service.RefreshTokenService;
import com.coderscampus.SpringSecurityJWTDemo.service.UserService;
import com.coderscampus.SpringSecurityJWTDemo.service.UserServiceImpl;

@Controller
public class RegistrationController {
	
	private Logger logger = LoggerFactory.getLogger(RegistrationController.class);

	@Autowired
	private UserServiceImpl userService;
	
	@Autowired
	private AuthenticationServiceImpl authenticationService;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private JwtServiceImpl jwtService;
	
	@Autowired
	private RefreshTokenService refreshTokenService;
	
	@GetMapping("/register")
	public String getRegistration (ModelMap model) {
		model.addAttribute("user", new User());
		return "registration";
	}
	
	
	@PostMapping("/register")
	public ModelAndView processRegistration (User user) {
		user.setFirstName(user.getFirstName());
		user.setLastName(user.getLastName());
		user.setEmail(user.getEmail());
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		
		User savedUser = userService.registerUser(user);
//		System.out.println(user.toString());
		
		String accessToken = jwtService.generateToken(new HashMap<>(), savedUser);
		RefreshToken refreshToken = refreshTokenService.createRefreshToken(savedUser.getId());
		
		ModelAndView modelAndView = new ModelAndView(new RedirectView("/signin"));
		
		return modelAndView;
		
	}

	
	
//	@PostMapping("/register")
//	public String processRegistration(@ModelAttribute("user") User user, SignUpRequest request) {
//	    Optional<User> existingUser = userService.findUserByEmail(user.getEmail());
//	    logger.info("Processing registration for user: " + user.getEmail());
//
//	    if (existingUser.isPresent()) {
//	    	logger.info("User already exists. Redirecting to userExists.");
//	        // Redirect to the userExists page if a user with the same email exists
//	        return "userExists";
//	    } else {
//	    	JwtAuthenticationResponse signupResponse = authenticationService.signup(request);
//
//	        if (signupResponse != null) {
//	            // Successfully registered user, now proceed with authentication
//	                logger.info("Successfully registered user. Redirecting to success.");
//	                return "success";
//	            } else {
//	                // Handle the case where authentication is not successful
//	            	logger.info("User registration failed. Redirecting to error.");
//	                return "error";
//	            }
//	        }
//	    }
	}

//  @PostMapping("/signup")
//  public ResponseEntity<JwtAuthenticationResponse> signup(@RequestBody SignUpRequest request) {
//      return ResponseEntity.ok(authenticationService.signup(request));
//  }

