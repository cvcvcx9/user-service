package com.cvcvcx.user_service.dto;

import lombok.Data;

@Data
public class RegisterRequestDto {
    private String email;
    private String password;
}