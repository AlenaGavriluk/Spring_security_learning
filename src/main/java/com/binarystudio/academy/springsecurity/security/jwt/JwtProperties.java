package com.binarystudio.academy.springsecurity.security.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtProperties {
	private String secret;
	private Long secs_to_expire_access;
	private Long secs_to_expire_refresh;
	private Long secs_to_expire_change_password;
}
