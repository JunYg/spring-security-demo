package club.junefory.spring.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;

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

    @Override
    public void configure(WebSecurity webSecurity) {
        webSecurity.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
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
        httpSecurity.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login.html")
                .loginProcessingUrl("/doLogin")
                .usernameParameter("username")
                .passwordParameter("password")
                .defaultSuccessUrl("/hello", true)
//                .successForwardUrl("/hello")
                .failureUrl("/error")
//                .successForwardUrl("/hello")
                .permitAll()
                .and()
                .logout().logoutRequestMatcher(new RegexRequestMatcher("/logout", "GET"))
                .logoutSuccessUrl("/logoutS")
                .and()
                .authorizeRequests()
                .mvcMatchers("/logoutS")
                .anonymous()
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
