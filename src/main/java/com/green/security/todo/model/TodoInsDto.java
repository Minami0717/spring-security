package com.green.security.todo.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TodoInsDto {
    private Long iuser;
    private String ctnt;
}
