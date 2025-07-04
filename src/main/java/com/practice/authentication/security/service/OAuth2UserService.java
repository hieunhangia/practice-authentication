package com.practice.authentication.security.service;

import com.practice.authentication.entity.User;
import com.practice.authentication.repository.RoleRepository;
import com.practice.authentication.repository.UserRepository;
import com.practice.authentication.security.entity.UserDetailsCustom;
import com.practice.authentication.security.utilities.SecurityUtils;
import com.practice.authentication.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class OAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    UserRepository userRepository;
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    SecurityUtils securityUtils;
    @Autowired
    RoleService roleService;

    public OAuth2User linkToGoogle(OAuth2User oauth2User, UserDetailsCustom currentUser) throws OAuth2AuthenticationException {
        if (userRepository.existsByEmail(oauth2User.getAttribute("email"))) {
            throw new OAuth2AuthenticationException(new OAuth2Error("account_already_linked"));
        } else {
            User user = userRepository.findByUsername(currentUser.getUsername()).orElseThrow();
            user.setEmail(oauth2User.getAttribute("email"));
            userRepository.save(user);
            return new UserDetailsCustom(user, oauth2User.getAttributes());
        }
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(request);
        String email = oauth2User.getAttribute("email");
        UserDetailsCustom currentUser = securityUtils.getCurrentUser();
        if (currentUser != null){
            return linkToGoogle(oauth2User, currentUser);
        }
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setUsername(oauth2User.getAttribute("name"));
                    newUser.setRoles(Set.of(roleService.getDefaultRole()));
                    newUser.setEmail(email);
                    return userRepository.save(newUser);
                });
        return new UserDetailsCustom(user, oauth2User.getAttributes());
    }

}
