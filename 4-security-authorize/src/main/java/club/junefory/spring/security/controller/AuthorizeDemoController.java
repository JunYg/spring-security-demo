package club.junefory.spring.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @description:
 * @author: Yang
 * @create: 2020-09-04 10:28
 **/
@RestController
public class AuthorizeDemoController {

    @GetMapping("/admin/hello")
    public String adminDemo() {
        return "Hello, Admin";
    }

    @GetMapping("/user/hello")
    public String userDemo() {
        return "Hello, User";
    }

    @GetMapping("/common/hello")
    public String commonHelloDemo() {
        return "Hello, Common";
    }

    @GetMapping("/common")
    public String commonDemo() {
        return "Hello, Common";
    }
}
