package com.coderscampus.SpringSecurityJWTDemo.web;

import com.coderscampus.SpringSecurityJWTDemo.domain.Authority;
import com.coderscampus.SpringSecurityJWTDemo.domain.Role;
import com.coderscampus.SpringSecurityJWTDemo.domain.User;
import com.coderscampus.SpringSecurityJWTDemo.repository.UserRepository;
import com.coderscampus.SpringSecurityJWTDemo.service.UserService;

import jakarta.annotation.PostConstruct;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
//@RestController
@Controller
@RequestMapping("/admin")
public class AdminController {
    private UserService userService;
    private UserRepository userRepo;
    private PasswordEncoder passwordEncoder;
    
    public AdminController(UserService userService, UserRepository userRepo, PasswordEncoder passwordEncoder) {
		super();
		this.userService = userService;
		this.userRepo = userRepo;
		this.passwordEncoder = passwordEncoder;
	}

    @PostConstruct
    public void init() {
    	// Create admin user during application startup
    	createAdminUser();
    }
    
	List<User> allAdmins = new ArrayList<>();

	
	public void createAdminUser() {
		User adminUser = new User();
		adminUser.setFirstName("Admin");
		adminUser.setLastName("User");
		adminUser.setEmail("admin@email.com");
		adminUser.setPassword(passwordEncoder.encode("adminPassword"));
//		adminUser.authority("ROLE_ADMIN");
		
		Authority adminAuth = new Authority("ROLE_ADMIN", adminUser);
		
//		adminUser.setAuthorities(List.of(adminAuth));
		adminUser.setAuthorities(Collections.singletonList(adminAuth));
		
		userRepo.save(adminUser);
	}

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers () {
        List<User> users = userService.findAll();
        return ResponseEntity.ok(users);
    }
    
    @GetMapping("/dashboard")
    public String getDashboard (ModelMap model) {
    	List<User> users = userService.findAll();
    	model.addAttribute(users);
    	return "dashboard";
    }
}
