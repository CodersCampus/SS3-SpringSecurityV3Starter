package com.coderscampus.SpringSecurityJWTDemo.dao.request;

public record SignUpRequest(String email, String password, String firstName, String lastName) {

}
