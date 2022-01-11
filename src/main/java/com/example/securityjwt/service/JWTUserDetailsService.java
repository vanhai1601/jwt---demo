package com.example.securityjwt.service;

import com.example.securityjwt.entity.Role;
import com.example.securityjwt.entity.User;
import com.example.securityjwt.repository.RoleRepository;
import com.example.securityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class JWTUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<SimpleGrantedAuthority> listRole = new ArrayList<>();
        User user = userRepository.findUserByUserName(username);
        if (user != null) {
            String[] roles = user.getRolesId().split(",");
            for (String roleCode : roles) {
                Role role = roleRepository.findRoleByCode(roleCode.trim());
                listRole.add(new SimpleGrantedAuthority(role.getName()));
            }
            return new org.springframework.security.core.userdetails.User(user.getUserName(), user.getPassword(), listRole);
        }
        throw new UsernameNotFoundException("User not found with the name " + username);
    }
}
