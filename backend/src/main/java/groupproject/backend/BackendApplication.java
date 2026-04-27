package groupproject.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

import groupproject.backend.config.DotenvConfig;

@SpringBootApplication
@EnableScheduling
public class BackendApplication {

    public static void main(String[] args) {
        // Load .env file before Spring Boot starts
        DotenvConfig.setSystemProperties();
        SpringApplication.run(BackendApplication.class, args);
    }

}
