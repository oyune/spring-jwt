package com.example.springusermanagement.user;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;

@Slf4j
@Component
public class JWTProvider {
    public JWTProvider(
            @Value("${jwt.secret}") String secretKey,
            @Value("${jwt.exprieIn}") long expireIn) {
    }
}
