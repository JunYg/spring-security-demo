package club.junefory.spring.security.config;

import club.junefory.spring.security.security.LoginAuthenticationFailureHandler;
import club.junefory.spring.security.security.LoginAuthenticationSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @description:
 * @author: Yang
 * @create: 2020-08-24 14:51
 **/
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 设置密码解密方式
     *
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * 登录成功过处理
     *
     * @return
     */
    @Bean
    public AuthenticationSuccessHandler loginAuthenticationSuccessHandler() {
        return new LoginAuthenticationSuccessHandler();
    }

    /**
     * 设置密码解密方式
     *
     * @return
     */
    @Bean
    public AuthenticationFailureHandler loginAuthenticationFailureHandler() {
        return new LoginAuthenticationFailureHandler();
    }

    /**
     * 配置角色拥有的资源权限
     * 支持3中URL 过滤机制
     * 1. ANT **
     * 2. regex 正则
     * 3. mvc ServletPath 以固定前缀开头
     *
     * @param httpSecurity
     */
    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeRequests().anyRequest().authenticated()
                .and()
                // 表单登录
                .formLogin()
                .loginProcessingUrl("/doLogin")
                .successHandler(this.loginAuthenticationSuccessHandler())
                .failureHandler(this.loginAuthenticationFailureHandler())
                .and()
                // 未认证请求处理
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                        response.getWriter().write("请登录");
                        response.getWriter().close();
                    }
                })
                .and()
                // 登出
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                        response.getWriter().write("注销成功");
                        response.getWriter().close();
                    }
                })
                .and()
                .csrf().disable();
    }

    /**
     * 配置授权管理器
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("123").roles("admin").authorities("role_user")
                .accountExpired(false).credentialsExpired(false).accountLocked(false).disabled(false)
                .and();
    }
}
