package groupproject.backend.config;

import org.springframework.context.annotation.Configuration;

import io.github.cdimascio.dotenv.Dotenv;
import jakarta.annotation.PostConstruct;

@Configuration
public class DotenvConfig {

    @PostConstruct
    public void loadEnv() {
        // .env is loaded in BackendApplication.main() before Spring context starts
    }

    public static void setSystemProperties() {
        try {
            // 1. Load .env (base config — DB credentials, JWT, etc.)
            Dotenv dotenv = Dotenv.configure()
                    .directory(".")
                    .ignoreIfMissing()
                    .load();
            dotenv.entries().forEach(entry -> {
                if (System.getProperty(entry.getKey()) == null) {
                    System.setProperty(entry.getKey(), entry.getValue());
                }
            });

            // 2. Load .env.local overrides — always wins over .env (git-ignored, local dev only)
            Dotenv dotenvLocal = Dotenv.configure()
                    .directory(".")
                    .filename(".env.local")
                    .ignoreIfMissing()
                    .load();
            dotenvLocal.entries().forEach(entry ->
                    System.setProperty(entry.getKey(), entry.getValue())
            );
        } catch (Exception e) {
            System.err.println("Warning: Could not load .env file: " + e.getMessage());
        }
    }
}
