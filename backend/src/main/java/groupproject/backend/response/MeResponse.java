package groupproject.backend.response;

import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MeResponse {
    @Nullable
    private String username;

    @Nullable
    private String email;

    @Nullable
    private String photo;

    @Nullable
    private String phoneNumber;

    @Nullable
    private String address;

    @Nullable
    private String bio;

    @Nullable
    private Set<String> roles;

}