package com.green.security.todo;

import com.green.security.config.security.model.MyUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/todo-api")
@RequiredArgsConstructor
public class TodoController {
    private final TodoService service;

    @PostMapping
    public int insTodo(@AuthenticationPrincipal MyUserDetails user, @RequestParam String ctnt) {
        log.info("TodoController - insTodo: ctnt {}", ctnt);
        log.info("controller-iuser {}", user.getIuser());
        service.test();
        return service.insTodo(user.getIuser(), ctnt);
    }
}
