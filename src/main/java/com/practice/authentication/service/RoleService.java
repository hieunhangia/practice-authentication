package com.practice.authentication.service;

import com.practice.authentication.entity.Role;
import com.practice.authentication.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RoleService {
    @Autowired
    private RoleRepository roleRepository;

    public Role getDefaultRole() {
        return roleRepository.findByName("User")
                .orElseGet(() -> {
                    Role roleUser = new Role("User");
                    roleRepository.save(roleUser);
                    return roleUser;
                });
    }
}
