package com.example.securityjwt.repository;

import com.example.securityjwt.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role,Integer> {
    @Query(value = "select r from Role r where r.code = ?1")
    Role findRoleByCode(String code);
}
