package com.green.security.todo;

import com.green.security.config.security.AuthenticationFacade;
import com.green.security.todo.model.TodoInsDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class TodoService {
    private final AuthenticationFacade facade;
    private final TodoMapper mapper;

    public void test() {
        log.info("service-test iuser : {}", facade.getLoginUserPk());
    }

    public int insTodo(Long iuser, String ctnt) {
        TodoInsDto dto = TodoInsDto.builder()
                .iuser(iuser)
                .ctnt(ctnt)
                .build();
        return mapper.insTodo(dto);
    }
}
