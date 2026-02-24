package groupproject.backend.response;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

import java.util.Set;

@Data
public class AuthResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("type")
    private String type = "Bearer";

    private Set<String> roles;

}
