package com.aiwatchdog.backend.fileshield.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(FileShieldProperties.class)
public class FileShieldConfiguration { }
