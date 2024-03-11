package com.example.springusermanagement.auth;

import com.example.springusermanagement.user.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class RegisterRequest {
    private String email;
    private String password;
    private String name;
    private Role role;
}
