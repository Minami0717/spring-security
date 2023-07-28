package com.green.security.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Todo list",
                description = "Spring Security Exam",
                version = "v0.0.1"
        )
)
@SecurityScheme(
        type = SecuritySchemeType.HTTP,
        name = "Authorization",
        scheme = "Bearer"
)
public class SwaggerConfiguration {}
