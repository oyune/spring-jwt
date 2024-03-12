package com.example.springusermanagement.user;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWTService {
    @Value("${application.security.jwt.secret}")
    private String jwtSecret;

    @Value("${application.security.jwt.expiration}")
    private String jwtExpiration;

    public String extractUsername(String token) {
        return null;
    }

    private Key getSignInKey() {
        byte[] keyByte = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyByte);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims); // 특정 클레임만 반환
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder() // JWT 파서 빌더 생성
                .setSigningKey(getSignInKey()) // 서명 검증에 사용될 키 생성
                .build() // JWT 파서 생성
                .parseClaimsJws(token) // 토큰 파싱 및 서명 검증
                .getBody(); // 클레임 추출
    }

    // 유저 정보를 통해 토큰 발급
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // 유저 정보 및 추가 클레임을 통해 토큰 발급
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails, Long.parseLong(jwtExpiration));
    }

    public String generateRefreshToken(
            UserDetails userDetails
    ) {
        return buildToken(new HashMap<>(), userDetails, Long.parseLong(jwtExpiration));
    }

    // JWT 토큰 생성
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims) // 추가 클레임 정보 설정
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // 유효한 토큰인지 검증
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // 만료된 토큰인지 체크
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // 토큰에서 만료시간 추출
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
