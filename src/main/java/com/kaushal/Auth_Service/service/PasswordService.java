package com.kaushal.Auth_Service.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class PasswordService {

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    // Method to hash the password.
    public String hashPassword(String password) {
        return passwordEncoder.encode(password);
    }

    // Method to verify raw password with hashed password.
    public boolean verifyPassword(String password, String hashedPassword) {
        return passwordEncoder.matches(password, hashedPassword);
    }
}
