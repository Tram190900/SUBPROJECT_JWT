package com.jwt.subproject_jwt.repository;

import com.jwt.subproject_jwt.enitity.Token;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenRepository
        extends JpaRepository<Token, Long> {
    Token findByToken(String token);
    Token saveAndFlush(Token token);
}
