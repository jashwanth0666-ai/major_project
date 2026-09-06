package com.aiwatchdog.backend;

import com.aiwatchdog.backend.config.MlServiceConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestClient;

@SpringBootApplication
@EnableConfigurationProperties(MlServiceConfig.class)
public class BackendApplication {

	@Bean
	RestClient.Builder restClientBuilder() {
		return RestClient.builder();
	}

	public static void main(String[] args) {
		SpringApplication.run(BackendApplication.class, args);
	}

}
