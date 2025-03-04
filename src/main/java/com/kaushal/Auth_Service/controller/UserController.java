package com.kaushal.Auth_Service.controller;

import com.kaushal.Auth_Service.dto.LoginRequest;
import com.kaushal.Auth_Service.entity.User;
import com.kaushal.Auth_Service.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/all-users")
    public ResponseEntity<List<User>> getAllUsers() {
        if (!userService.getAllUsers().isEmpty()) {
            return new ResponseEntity<>(userService.getAllUsers(), HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/signup")
    public ResponseEntity<User> signup(@RequestBody User newUser) {
        return new ResponseEntity<>(userService.createUser(newUser), HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<String> signin(@RequestBody LoginRequest loginRequest) {
        String token = userService.signInUser(loginRequest.getEmail(), loginRequest.getPassword());
        return new ResponseEntity<>(token, HttpStatus.OK);
    }

    @GetMapping("/user-info")
    public ResponseEntity<HashMap<String, String>> fetchUserInfoByToken(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        String token = authHeader.replace("Bearer ", "").trim();
        HashMap<String, String> user = userService.fetchUserInfoByToken(token);
        if (user != null) {
            return new ResponseEntity<>(user, HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    @GetMapping("/other-user-info")
    public ResponseEntity<HashMap<String, String>> fetchOtherUserInfo(@RequestHeader("Authorization") String authHeader,
                                                                      @RequestBody String email, @RequestHeader String userID) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        String token = authHeader.replace("Bearer ", "").trim();
        HashMap<String, String> user = userService.fetchUserInfoById(token, email, userID);
        if (user != null) {
            return new ResponseEntity<>(user, HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
}
