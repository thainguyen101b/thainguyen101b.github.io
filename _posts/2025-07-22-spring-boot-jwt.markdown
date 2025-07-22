---
layout: post
title: 'Spring Boot + JWT'
date: 2025-07-22 09:54:35 +0700
categories: [spring-security, jwt]
---

## 1. Tạo dự án Spring Boot tại start.spring.io

Truy cập [start.spring.io](https://start.spring.io) và cấu hình như sau:

- **Project**: Maven
- **Language**: Java
- **Java Version**: 17
- **Spring Boot Version**: 3.x.x hoặc mới hơn
- **Dependencies**: `Spring Web`, `Spring Security`, `Lombok`

Sau đó nhấn `Generate` hoặc `Ctrl + ⏎`

## 2. Cơ chế tự động cấu hình của Spring Security

Theo mặc định, Spring Security sử dụng `form login` và `InMemoryUserDetailsManager`. Bạn có thể chạy dự án bằng `mvn spring-boot:run` và quan sát log.
Về cơ bản log sẽ như sau:

```txt
2025-07-21T10:40:19.463+07:00  INFO 14716 --- [demo] [           main] com.example.springbootjwt.SpringBootJwtApplication           : No active profile set, falling back to 1 default profile: "default"
2025-07-21T10:40:20.145+07:00  INFO 14716 --- [demo] [           main] o.s.b.w.embedded.tomcat.TomcatWebServer                      : Tomcat initialized with port 8080 (http)
2025-07-21T10:40:20.155+07:00  INFO 14716 --- [demo] [           main] o.apache.catalina.core.StandardService                       : Starting service [Tomcat]
2025-07-21T10:40:20.155+07:00  INFO 14716 --- [demo] [           main] o.apache.catalina.core.StandardEngine                        : Starting Servlet engine: [Apache Tomcat/10.1.42]
2025-07-21T10:40:20.185+07:00  INFO 14716 --- [demo] [           main] o.a.c.c.C.[Tomcat].[localhost].[/]                           : Initializing Spring embedded WebApplicationContext
2025-07-21T10:40:20.186+07:00  INFO 14716 --- [demo] [           main] w.s.c.ServletWebServerApplicationContext                     : Root WebApplicationContext: initialization completed in 695 ms
2025-07-21T10:40:20.433+07:00  WARN 14716 --- [demo] [           main] .s.s.UserDetailsServiceAutoConfiguration                     :

Using generated security password: 18010b3d-ca15-40bc-854b-bd677d5bf4a1

This generated password is for development use only. Your security configuration must be updated before running your application in production.

2025-07-21T10:40:20.437+07:00  INFO 14716 --- [demo] [           main] r$InitializeUserDetailsManagerConfigurer                     : Global AuthenticationManager configured with UserDetailsService bean with name inMemoryUserDetailsManager
2025-07-21T10:40:20.510+07:00  INFO 14716 --- [demo] [           main] o.s.b.w.embedded.tomcat.TomcatWebServer                      : Tomcat started on port 8080 (http) with context path '/'
2025-07-21T10:40:20.514+07:00  INFO 14716 --- [demo] [           main] com.example.springbootjwt.SpringBootJwtApplication           : Started SpringBootJwtApplication in 1.449 seconds (process running for 1.95)
```

## 3. Chuẩn bị các dependencies cần thiết

Để xây dựng được một dự án với `Spring Security + JWT + User Management` vốn khá phổ biến trong các dự án vừa và nhỏ, hoặc nội bộ. Hãy thêm những thư viện này vào `pom.xml`

`jjwt`

{% highlight xml %}
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.3</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.12.3</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.3</version>
</dependency>
{% endhighlight %}

`Spring Data JPA`

{% highlight xml %}
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
{% endhighlight %}

`Postgres Driver`

{% highlight xml %}
<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <scope>runtime</scope>
</dependency>
{% endhighlight %}

## 4. Thiết kế các Entity cần thiết

Trong tài liệu Spring Security chính thức, họ sử dụng `UserDetails` và triển khai của nó là `User` để quản lý `credentials`, và `Collection<GrantedAuthority>` để quản lý `authorities`.

Bạn có thể tham khảo [Default Schema](https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/jdbc.html#servlet-authentication-jdbc-schema).

`User.java`
{% highlight java %}
package com.example.springbootjwt.user;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

@Getter
@Setter
@Entity
@Table(name = "users")
public class User {
@Id
@GeneratedValue(strategy = GenerationType.IDENTITY)
@Column(name = "id", nullable = false)
private Long id;

    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @Column(name = "password", nullable = false)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "users_authorities",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "authorities_id"))
    private Set<Authority> authorities = new LinkedHashSet<>();

    public User() {
    }

    public User(String username, String password, Authority... authorities) {
        this.username = username;
        this.password = password;
        this.authorities = new LinkedHashSet<>(Arrays.asList(authorities));
    }

}
{% endhighlight %}

`Authority.java`
{% highlight java %}
package com.example.springbootjwt.user;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "authorities")
public class Authority {
@Id
@GeneratedValue(strategy = GenerationType.IDENTITY)
@Column(name = "id", nullable = false)
private Long id;

    @Column(name = "authority", nullable = false, unique = true)
    private String authority;

    public Authority() {
    }

    public Authority(String authority) {
        this.authority = authority;
    }

}
{% endhighlight %}

`RefreshToken.java`
{% highlight java %}
package com.example.springbootjwt.user;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "refresh_token")
public class RefreshToken {
@Id
@GeneratedValue(strategy = GenerationType.IDENTITY)
@Column(name = "id", nullable = false)
private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "token", nullable = false, unique = true, length = 512)
    private String token;

    @Column(name = "expiry_date")
    private Instant expiryDate;

    private Boolean revoked;

    public RefreshToken() {
    }

    public RefreshToken(User user, String token, Instant expiryDate) {
        this.user = user;
        this.token = token;
        this.expiryDate = expiryDate;
        this.revoked = false;
    }

}
{% endhighlight %}

`Role.java`
{% highlight java %}
package com.example.springbootjwt.user;

public final class Role {
private Role() {
}

    public static final String USER = "USER";
    public static final String ADMIN = "ADMIN";
    public static final String MODERATOR = "MODERATOR";

}
{% endhighlight %}

`UserRepository.java`
{% highlight java %}
package com.example.springbootjwt.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);

}
{% endhighlight%}

`AuthorityRepository.java`
{% highlight java %}
package com.example.springbootjwt.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthorityRepository extends JpaRepository<Authority, Long> {
    Optional<Authority> findByAuthority(String authority);
}
{% endhighlight %}

`RefreshTokenRepository.java`
{% highlight java %}
package com.example.springbootjwt.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findFirstByUserAndRevokedFalseAndExpiryDateIsAfter(User user, Instant expiryDateAfter);

}
{% endhighlight %}

`application.properties`

{% highlight properties %}
spring.application.name=spring-boot-jwt

logging.level.org.springframework.security=debug

spring.datasource.url=jdbc:postgresql://localhost:5432/demo
spring.datasource.username=postgres
spring.datasource.password=postgres

spring.jpa.hibernate.ddl-auto=update
{% endhighlight %}

## 5. Cấu hình Authentication Manager

Vì hệ thống đang quản lý entity `User` riêng, nên cần custom lại bean `UserDetailsService`

`CustomeUserDetailsService.java`
{% highlight java %}
package com.example.springbootjwt.security;

import com.example.springbootjwt.user.User;
import com.example.springbootjwt.user.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class CustomeUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomeUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities().stream()
                        .map(authority -> new SimpleGrantedAuthority(
                                "ROLE_" + authority.getAuthority().toUpperCase()))
                        .toList()
        );
    }

}
{% endhighlight %}

`PasswordEncoder bean`
{% highlight java %}
package com.example.springbootjwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            CustomeUserDetailsService customeUserDetailsService,
            PasswordEncoder passwordEncoder
    ) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(customeUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(authProvider);
    }

}
{% endhighlight %}

Trong các ứng dụng web dùng `Spring Boot` và xác thực dựa trên token, đây là những thực tiễn tốt khi xây dựng bean `SecurityFilterChain`

* CSRF disable
* Session policy STATELESS
* Ghi đè lại `AuthenticationEntryPoint`

Bean `SecurityFilterChain` đầy đủ

{% highlight java %}
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                CustomeAuthenticationEntryPoint customeAuthenticationEntryPoint)
        throws Exception {

    return http.csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(authz -> authz
                    // Public endpoints
                    .requestMatchers("/auth/**").permitAll()

                    .requestMatchers("/").hasAnyRole(USER, ADMIN, MODERATOR)

                    .requestMatchers("/mod").hasAnyRole(ADMIN, MODERATOR)

                    .requestMatchers("/admin").hasRole(ADMIN)

                    .anyRequest().authenticated()
            )
            .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> ex
                    .authenticationEntryPoint(customeAuthenticationEntryPoint))
            .build();
}
{% endhighlight %}

Trong phần `authorizeHttpRequests` cả ba endpoints `/`, `/mod` và `/admin` đều yêu cầu xác thực. Trong đó

* `/` cần có role `USER` hoặc `MODERATOR` hoặc `ADMIN`
* `/mod` cần có role `MODERATOR` hoặc `ADMIN`
* `/admin` cần có role `ADMIN`

Trong Spring Security Role based access control (RBAC), các role như `USER`, `MODERATOR`,... thực chất là đối tượng `SimpleGrantedAuthority("ROLE_USER")`, `SimpleGrantedAuthority("ROLE_MODERATOR")`,... 
Theo quy tắc của `GrantedAuthority` nhận vào 1 tham số gọi là `authority` và chúng sẽ được dùng theo dạng `hasAuthority`, `hasAnyAuthority`,... 

Mặt khác, khi muốn sử dụng `hasRole`, `hasAnyRole` thì mỗi `authority` của `GrantedAuthority` cần có tiền tố `ROLE_`

`CustomeAuthenticationEntryPoint.java`
{% highlight java %}
package com.example.springbootjwt.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomeAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // This is invoked when user tries to access a secured REST resource without supplying any credentials
        // We should just send a 401 Unauthorized response because there is no 'login page' to redirect to
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
    }
}
{% endhighlight %}

> Bean này được gọi khi người dùng cố gắng truy cập secured REST resource mà không cung cấp bất kỳ thông tin xác thực nào. 
> 
> Chúng ta chỉ nên gửi response `401 Unauthorized` vì không có 'trang đăng nhập' nào để chuyển hướng đến.

## 6. Viết Jwt generator

Thêm các thuộc tính sau vào cuối của `application.properties`

{% highlight properties %}
jwt.secret=LqvFTN5t8DTlitc5SjfuQFnHlOxRWjZExRkVkaNuC9A6hsBnoH8RhqIyrbCUsCTn9lfoZaLXiLFh2bOur34nWA==
jwt.expiration=3600000
jwt.refresh-token.expiration=604800000
{% endhighlight %}

Để tạo ra chuỗi secret mạnh mẽ và đủ dài. Sử dụng lệnh sau:
{% highlight bash %}
openssl rand -base64 64
{% endhighlight %}

Đối với Windows thì có thể dùng `Git Bash`

`JwtProvider.java`

{% highlight java %}
package com.example.springbootjwt.security;

import com.example.springbootjwt.user.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtProvider {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    @Value("${jwt.refresh-token.expiration}")
    private long refreshTokenExpiration;

    public String generateToken(User user) {
        return buildToken(new HashMap<>(), user, expiration);
    }

    public String generateRefreshToken(User user) {
        return buildToken(new HashMap<>(), user, refreshTokenExpiration);
    }

    public void validateToken(String token) {
        Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token);
    }

    public String extractUsername(String token) {
        return Jwts.parser().verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload().get("username", String.class);
    }

    private String buildToken(Map<String, Object> extraClaims, User user, long expiration) {
        extraClaims.put("username",  user.getUsername());
        extraClaims.put("roles", user.getAuthorities().stream()
                .map(authority -> authority.getAuthority().toUpperCase())
                .toList());

        return Jwts.builder()
                .subject(user.getId().toString())
                .claims(extraClaims)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), Jwts.SIG.HS256)
                .compact();
    }

    private SecretKey getSignInKey() {
        byte[] bytes = secret.getBytes();
        return Keys.hmacShaKeyFor(bytes);
    }
}
{% endhighlight %}

`JwtAuthenticationFilter.java`

{% highlight java %}
package com.example.springbootjwt.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHENTICATION_SCHEMA = "Bearer";
    private final JwtProvider jwtProvider;
    private final CustomeUserDetailsService customeUserDetailsService;

    public JwtAuthenticationFilter(JwtProvider jwtProvider, CustomeUserDetailsService customeUserDetailsService) {
        this.jwtProvider = jwtProvider;
        this.customeUserDetailsService = customeUserDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (!isTokenBasedAuthentication(authorizationHeader)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader
                .substring(AUTHENTICATION_SCHEMA.length()).trim();

        // validate token
        jwtProvider.validateToken(token);

        String username = jwtProvider.extractUsername(token);
        UserDetails userDetails = customeUserDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }

    private boolean isTokenBasedAuthentication(String authorizationHeader) {
        return authorizationHeader != null &&
                authorizationHeader.toLowerCase().startsWith(AUTHENTICATION_SCHEMA.toLowerCase() + " ");
    }
}
{% endhighlight %}

Cập nhật lại bean `SecurityFilterChain`

{% highlight java %}
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                JwtAuthenticationFilter jwtAuthenticationFilter,
                                                CustomeAuthenticationEntryPoint customeAuthenticationEntryPoint)
        throws Exception {

    return http.csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(authz -> authz
                    // Public endpoints
                    .requestMatchers("/auth/**").permitAll()

                    .requestMatchers("/").hasAnyRole(USER, ADMIN, MODERATOR)

                    .requestMatchers("/mod").hasAnyRole(ADMIN, MODERATOR)

                    .requestMatchers("/admin").hasRole(ADMIN)

                    .anyRequest().authenticated()
            )
            .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> ex
                    .authenticationEntryPoint(customeAuthenticationEntryPoint))
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
}
{% endhighlight %}

## 7. Triển khai phần còn lại (Login/Register)

Mọi thứ ở phía sau hậu trường đã xong, giờ sẽ triển khai tầng `Service` và tầng `Controller`

`UserService.java`

{% highlight java %}
package com.example.springbootjwt.user.service;

import com.example.springbootjwt.user.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;

    public UserService(PasswordEncoder passwordEncoder, UserRepository userRepository, AuthorityRepository authorityRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.authorityRepository = authorityRepository;
    }

    public User createUser(String username, String password){
        if (userRepository.existsByUsername(username)){
            throw new IllegalArgumentException("Username already exists");
        }

        Authority defaultAuthority = authorityRepository.findByAuthority(Role.USER)
                .orElseGet(() -> authorityRepository.save(new Authority(Role.USER)));

        User user = new User(username, passwordEncoder.encode(password), defaultAuthority);
        return userRepository.save(user);
    }

}
{% endhighlight %}

`RefreshTokenService.java`

{% highlight java %}
package com.example.springbootjwt.user.service;

import com.example.springbootjwt.security.JwtProvider;
import com.example.springbootjwt.user.RefreshToken;
import com.example.springbootjwt.user.RefreshTokenRepository;
import com.example.springbootjwt.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    @Value("${jwt.refresh-token.expiration}")
    private long jwtRefreshTokenExpiration;

    private final JwtProvider jwtProvider;

    public RefreshTokenService(JwtProvider jwtProvider, RefreshTokenRepository refreshTokenRepository) {
        this.jwtProvider = jwtProvider;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public String getOrCreateRefreshToken(User user) {
        return refreshTokenRepository.findFirstByUserAndRevokedFalseAndExpiryDateIsAfter(user, Instant.now())
                .map(RefreshToken::getToken)
                .orElseGet(() -> generateRefreshToken(user));
    }

    public String generateRefreshToken(User user) {
        String token = jwtProvider.generateRefreshToken(user);
        RefreshToken refreshToken = new RefreshToken(
                user,
                token,
                Instant.now().plusMillis(jwtRefreshTokenExpiration));

        refreshTokenRepository.save(refreshToken);
        return token;
    }

    @Transactional
    public String rotateRefreshToken(String oldToken) {
        RefreshToken oldStored = refreshTokenRepository.findByToken(oldToken)
                .orElseThrow(() -> new IllegalArgumentException("Invalid token when rotate refresh token"));
        if (oldStored.getRevoked() || oldStored.getExpiryDate().isBefore(Instant.now())) {
            throw new IllegalArgumentException("Refresh token expired or revoked");
        }

        oldStored.setRevoked(true); // auto flush

        User user = oldStored.getUser();
        return getOrCreateRefreshToken(user);
    }
}
{% endhighlight %}

`AuthController.java`

{% highlight java %}
package com.example.springbootjwt.controller;

import com.example.springbootjwt.controller.request.LoginRequest;
import com.example.springbootjwt.controller.request.RefreshTokenRequest;
import com.example.springbootjwt.controller.request.RegisterRequest;
import com.example.springbootjwt.controller.response.TokenResponse;
import com.example.springbootjwt.security.JwtProvider;
import com.example.springbootjwt.user.User;
import com.example.springbootjwt.user.UserRepository;
import com.example.springbootjwt.user.service.RefreshTokenService;
import com.example.springbootjwt.user.service.UserService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;

    public AuthController(AuthenticationManager authenticationManager, 
                          JwtProvider jwtProvider, 
                          UserRepository userRepository, 
                          RefreshTokenService refreshTokenService, 
                          UserService userService) {
        this.authenticationManager = authenticationManager;
        this.jwtProvider = jwtProvider;
        this.userRepository = userRepository;
        this.refreshTokenService = refreshTokenService;
        this.userService = userService;
    }

    @PostMapping("/auth/login")
    public TokenResponse login(@RequestBody LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new UsernameNotFoundException(request.username()));
        String accessToken = jwtProvider.generateToken(user);
        String refreshToken = refreshTokenService.getOrCreateRefreshToken(user);
        return new TokenResponse(accessToken, refreshToken);
    }

    @PostMapping("/auth/register")
    public TokenResponse register(@RequestBody RegisterRequest request) {
        User user = userService.createUser(request.username(), request.password());
        String accessToken = jwtProvider.generateToken(user);
        String refreshToken = refreshTokenService.generateRefreshToken(user);

        return new TokenResponse(accessToken, refreshToken);
    }

    @PostMapping("/auth/refresh-token")
    public TokenResponse refreshToken(@RequestBody RefreshTokenRequest request) {
        String newRefreshToken = refreshTokenService.rotateRefreshToken(request.refreshToken());
        String username = jwtProvider.extractUsername(newRefreshToken);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));
        String accessToken = jwtProvider.generateToken(user);
        return new TokenResponse(accessToken, newRefreshToken);
    }

}


package com.example.springbootjwt.controller.request;

public record LoginRequest(
        String username,
        String password
) {
}

package com.example.springbootjwt.controller.request;

public record RegisterRequest(
        String username,
        String password
) {
}

package com.example.springbootjwt.controller.request;

public record RefreshTokenRequest(
        String refreshToken
) {
}

package com.example.springbootjwt.controller.response;

public record TokenResponse(
        String accessToken,
        String refreshToken
) {
}
{% endhighlight %}

`DemoController.java`

{% highlight java %}
package com.example.springbootjwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'MODERATOR')")
    public String greeting(Authentication auth) {
        return "Hello " + auth.getName();
    }

    @GetMapping("/mod")
    @PreAuthorize("hasAnyRole('ADMIN', 'MODERATOR')")
    public String greetingMod(Authentication auth) {
        return "Hello mod " + auth.getName();
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String greetingAdmin(Authentication auth) {
        return "Hello admin " + auth.getName();
    }

}
{% endhighlight %}

## 8. Mock data

Thêm bean này vào class `Application` chứa `main`

{% highlight java %}
package com.example.springbootjwt;

import com.example.springbootjwt.user.*;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@SpringBootApplication
public class SpringBootJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootJwtApplication.class, args);
    }

    @Bean
    CommandLineRunner setupData(UserRepository userRepository,
                                PasswordEncoder passwordEncoder,
                                AuthorityRepository authorityRepository, RefreshTokenRepository refreshTokenRepository) {
        return args -> {
            refreshTokenRepository.deleteAll();
            userRepository.deleteAll();
            authorityRepository.deleteAll();

            var userAuthority = new Authority(Role.USER);
            var modAuthority = new Authority(Role.MODERATOR);
            var adminAuthority = new Authority(Role.ADMIN);
            authorityRepository.saveAll(List.of(userAuthority, modAuthority, adminAuthority));

            User user = new User("user", passwordEncoder.encode("user"), userAuthority);
            User mod = new User("mod", passwordEncoder.encode("mod"), modAuthority);
            User admin = new User("admin", passwordEncoder.encode("admin"), adminAuthority);

            userRepository.saveAll(List.of(user, mod, admin));
        };
    }

}
{% endhighlight %}

## 9. Conclusion

Như vậy là đã xong phần `code example` cho ứng dụng web dùng `Spring Boot + JWT`.

#### Những tính năng đã làm được:

* Dùng thư viện `jjwt` với thuật toán ký `HS256` + `secret key`
* Register
* Login với `Username/Password` 
* Refresh Token
* Cơ chế blacklist cho `refresh token`
* RBAC và tận dụng `@PreAuthorize`

Mã nguồn trên có ở [Github](https://github.com/thainguyen101b/spring-boot-jwt).