package com.green.security.todo;

import com.green.security.todo.model.TodoInsDto;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface TodoMapper {
    int insTodo(TodoInsDto dto);
}
