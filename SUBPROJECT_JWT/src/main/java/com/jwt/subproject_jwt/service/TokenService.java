package com.jwt.subproject_jwt.service;

import com.jwt.subproject_jwt.enitity.Token;

public interface TokenService {
    Token createToken(Token token);

    Token findByToken(String token);
}