package groupproject.backend.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AuthLoginRequest {

    @NotBlank(message = "Email is required")
    @JsonProperty("username")
    private String username;

    @NotBlank(message = "Password is required")
    @JsonProperty("password")
    private String password;
}

