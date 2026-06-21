package jcss.soft.com.auth_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@SpringBootApplication
@EnableJpaRepositories
public class AuthServiceApplication {
	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}
}


