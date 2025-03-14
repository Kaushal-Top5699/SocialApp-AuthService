package com.kaushal.Auth_Service.service;

import com.kaushal.Auth_Service.entity.User;
import com.kaushal.Auth_Service.repository.UserRepository;
import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


import java.util.HashMap;
import java.util.List;
import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordService passwordService;

    @Autowired
    private JWTService jwtService;

    // User service methods.
    // Get all users.
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    // Find a user by email.
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    // Create a new user and save to database.
    public String createUser(User newUser) {
        if (userRepository.findByEmail(newUser.getEmail()).isPresent()) {
            return "User with this email already exists try logging in.";
        }
        // Password hashing.
        newUser.setPassword(passwordService.hashPassword(newUser.getPassword()));
        // Save the user to db and return the user.
        userRepository.save(newUser);
        return "User Created!";
    }

    // User login.
    public String signInUser(String email, String password) {
        Optional<User> user = userRepository.findByEmail(email);
        if (user.isPresent() && passwordService.verifyPassword(password, user.get().getPassword())) {
            return jwtService.generateToken(email);
        } else {
            throw new RuntimeException("Invalid Credentials.");
        }
    }

    // Logged in user info.
    public HashMap<String, String> fetchUserInfoByToken(String token) {
        if (jwtService.isTokenExpired(token)) {
            return null;
        }
        String email = jwtService.extractEmail(token);
        Optional<User> targetUser = userRepository.findByEmail(email);
        if (targetUser.isPresent()) {
            User user = targetUser.get();
            HashMap<String, String> userInfo = new HashMap<>();
            userInfo.put("ObjectID", user.getId().toString());
            userInfo.put("email", user.getEmail());
            userInfo.put("firstName", user.getFirstName());
            userInfo.put("lastName", user.getLastName());
            userInfo.put("gender", user.getGender());
            userInfo.put("dob", user.getDob());
            userInfo.put("phoneNum", user.getPhoneNum());
            userInfo.put("userImage", user.getUserImage());
            return userInfo;
        }
        return null;
    }

    // Other user's profile info.
    public HashMap<String, String> fetchUserInfoById(String token, String email, String userID) {
        if (jwtService.isTokenExpired(token) && !jwtService.isTokenValid(token, email)) {
            return null;
        }
        ObjectId id = new ObjectId(userID);
        Optional<User> targetUser = userRepository.findById(id);
        if (targetUser.isPresent()) {
            User user = targetUser.get();
            HashMap<String, String> userInfo = new HashMap<>();
            userInfo.put("ObjectID", user.getId().toString());
            userInfo.put("email", user.getEmail());
            userInfo.put("firstName", user.getFirstName());
            userInfo.put("lastName", user.getLastName());
            userInfo.put("gender", user.getGender());
            userInfo.put("dob", user.getDob());
            userInfo.put("phoneNum", user.getPhoneNum());
            userInfo.put("userImage", user.getUserImage());
            return userInfo;
        }
        return null;
    }

    // Token Validity
    public Boolean isTokenValid(String token, String email) {
        return jwtService.isTokenValid(token, email) && !jwtService.isTokenExpired(token);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return (UserDetails) userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
    }
}
