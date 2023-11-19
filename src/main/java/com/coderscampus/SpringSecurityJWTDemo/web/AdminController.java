package com.coderscampus.SpringSecurityJWTDemo.web;

import com.coderscampus.SpringSecurityJWTDemo.domain.User;
import com.coderscampus.SpringSecurityJWTDemo.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
@RestController
@RequestMapping("/admin")
public class AdminController {
    private UserDetailsService userDetailsService;

    public AdminController(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

//    @GetMapping("/users")
//    public ResponseEntity<List<User>> getAllUsers () {
//        List<User> users = userDetailsService.findAll();
//        return ResponseEntity.ok(users);
//    }
}
