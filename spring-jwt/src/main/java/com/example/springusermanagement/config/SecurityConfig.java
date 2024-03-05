package com.example.springusermanagement.config;

import com.example.springusermanagement.handler.JWTAccessDeniedHandler;
import com.example.springusermanagement.handler.JWTAuthenticationEntryPoint;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {

    private final JWTAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JWTAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // token 인증 방식을 사용하므로 csrf에 대한 보호 비활성화
                .csrf(AbstractHttpConfigurer::disable)
                // 세션을 사용하지 않으므로 stateless로 설정
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 인증 및 접근 거부에 대한 핸들러 처리
                .exceptionHandling(exceptionHandlingConfigurer ->
                        exceptionHandlingConfigurer
                                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                                .accessDeniedHandler(jwtAccessDeniedHandler)
                )
                // 회원가입, 로그인의 경우 별도의 인증 없이 접근할 수 있도록 허용
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/api/authenticate").permitAll() // 로그인 허용
                                .requestMatchers("/api/signup").permitAll() // 회원가입 허용
                                .anyRequest().authenticated()
                );

        return httpSecurity.build();
    }
}
