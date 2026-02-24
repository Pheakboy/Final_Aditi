package groupproject.backend.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtProperties {

    @NotBlank
    private String secret;

    @Min(60000)
    private long expiration = 1000 * 60 * 10; // 10 minute

    @Min(60000)
    private long refreshExpiration = 1000 * 60 * 60 * 2; // 2 hours
}
