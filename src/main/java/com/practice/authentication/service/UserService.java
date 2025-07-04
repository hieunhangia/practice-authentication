package com.practice.authentication.service;

import com.practice.authentication.dto.ChangePasswordRequest;
import com.practice.authentication.dto.RegisterRequest;
import com.practice.authentication.entity.Role;
import com.practice.authentication.entity.User;
import com.practice.authentication.repository.RoleRepository;
import com.practice.authentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public void register(RegisterRequest request) {
        if (!request.getConfirmPassword().equals(request.getPassword()))
            throw new RuntimeException("Passwords do not match");
        if (userRepository.existsByUsername(request.getUsername()))
            throw new RuntimeException("Username or Email already taken");
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRoles(Set.of(getDefaultRole()));
        userRepository.save(user);
    }

    public void changePassword(String username, ChangePasswordRequest req) {
        User user = userRepository.findByUsername(username).orElseThrow();
        if (!req.getNewPassword().equals(req.getConfirmNewPassword())) {
            throw new RuntimeException("Passwords do not match");
        }
        if (!passwordEncoder.matches(req.getOldPassword(), user.getPassword()))
            throw new RuntimeException("Incorrect old password");
        user.setPassword(passwordEncoder.encode(req.getNewPassword()));
        userRepository.save(user);
    }

    private Role getDefaultRole(){
        return roleRepository.findByName("User")
                .orElseGet(() -> {
                    Role roleUser = new Role("User");
                    roleRepository.save(roleUser);
                    return roleUser;
                });
    }

}
