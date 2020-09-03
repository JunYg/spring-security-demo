package club.junefory.spring.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @description:
 * @author: Yang
 * @create: 2020-09-02 11:49
 **/
@RestController
public class HelloController {

    @PostMapping("doLogin")
    public String doLogin() {
        return "login success";
    }

    @GetMapping("logoutS")
    public String logout() {
        return "logout success";
    }

    @GetMapping("hello")
    public String hello() {
        return "Hello, Spring Security;";
    }
}
