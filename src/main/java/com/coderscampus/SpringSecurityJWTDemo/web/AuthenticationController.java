package com.coderscampus.SpringSecurityJWTDemo.web;

import java.util.HashMap;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import com.coderscampus.SpringSecurityJWTDemo.dao.request.SignInRequest;
import com.coderscampus.SpringSecurityJWTDemo.dao.request.SignUpRequest;
import com.coderscampus.SpringSecurityJWTDemo.dao.request.TokenRefreshRequest;
import com.coderscampus.SpringSecurityJWTDemo.dao.response.JwtAuthenticationResponse;
import com.coderscampus.SpringSecurityJWTDemo.dao.response.TokenRefreshResponse;
import com.coderscampus.SpringSecurityJWTDemo.domain.RefreshToken;
import com.coderscampus.SpringSecurityJWTDemo.domain.User;
import com.coderscampus.SpringSecurityJWTDemo.security.AuthenticationService;
import com.coderscampus.SpringSecurityJWTDemo.security.AuthenticationServiceImpl;
import com.coderscampus.SpringSecurityJWTDemo.security.JwtService;
import com.coderscampus.SpringSecurityJWTDemo.service.RefreshTokenService;
import com.coderscampus.SpringSecurityJWTDemo.service.UserServiceImpl;

//@RestController
//@RequestMapping("/api/v1/auth")
@Controller
public class AuthenticationController {
    private final AuthenticationServiceImpl authenticationService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    
    public AuthenticationController(AuthenticationServiceImpl authenticationService, RefreshTokenService refreshTokenService, JwtService jwtService) {
        super();
        this.authenticationService = authenticationService;
        this.refreshTokenService = refreshTokenService;
        this.jwtService = jwtService;
    }
    
    @Autowired
    private UserServiceImpl userService;

    @GetMapping("/signin")
	public String getLogin (@ModelAttribute("user") User user) {
		return "login";
	}
    
    @PostMapping("/signin")
    public ResponseEntity<JwtAuthenticationResponse> signin(@RequestBody SignInRequest request, @RequestBody User user) {
    	Optional<User> existingUser = userService.findUserByEmail(user.getEmail());
    	User loggedUser = ((User) userService).loadUserByUsername(user.getUsername());
    	String accessToken = jwtService.generateToken(user);
    	
        return ResponseEntity.ok(authenticationService.signin(request));
    }
    
//    @PostMapping("/signin")
//    public String authenticateLogin (@ModelAttribute("user") User user, SignInRequest request) {
//    	Optional<User> existingUser = userService.findUserByEmail(user.getEmail());
//    	
//    	if (existingUser.isPresent()) {
//            // User exists; proceed with authentication
//            JwtAuthenticationResponse authenticationResponse = authenticationService.signin(request);
//
//            if (authenticationResponse != null) {
//                // Authentication successful; you can proceed as needed
//                return "success"; // Redirect to a success page
//            } else {
//                // Handle unsuccessful authentication (e.g., wrong password)
//                return "error"; // Redirect to an error page
//            }
//        } else {
//            // Handle the case where the user does not exist
//            return "userNotExists"; // Redirect to a userNotExists page
//        }
//    }
    
//    @PostMapping("/signin")
//    public ModelAndView authenticateLogin(@RequestBody User user, SignInRequest request) {
//    	Optional<User> loggedUser = userService.findUserByEmail(user.getEmail());
//    	
//    	String accessToken = jwtService.generateToken(user);
//    	
//    	RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());
//    	
//    	return new ModelAndView(new RedirectView("/success"));
//    }
    
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@RequestBody TokenRefreshRequest request) {
      String requestRefreshToken = request.refreshToken();

      return refreshTokenService.findByToken(requestRefreshToken)
          .map(refreshTokenService::verifyExpiration)
          .map(RefreshToken::getUser)
          .map(user -> {
            String token = jwtService.generateToken(user);
            return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
          })
          .orElseThrow(() -> new IllegalStateException(
              "Refresh token " + requestRefreshToken + " is not in database!"));
    }
}