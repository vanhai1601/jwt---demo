package com.example.securityjwt.repository;

import com.example.securityjwt.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenRepository extends JpaRepository<Token, Integer> {
    @Query(value = "select t from Token t where  t.userId = ?1")
    Token findTokenByUserId(int userId);

    @Query(value = "select t from Token t where  t.refreshToken = ?1")
    Token findTokenByRefreshToken(String refreshToken);

    @Query(value = "select t from Token t where  t.token = ?1")
    Token findTokenByToken(String token);

}
