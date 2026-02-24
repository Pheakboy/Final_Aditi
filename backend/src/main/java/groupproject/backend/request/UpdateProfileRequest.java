package groupproject.backend.request;

import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UpdateProfileRequest {

    @Size(min = 1, max = 50, message = "Username must be between 1 and 50 characters")
    private String username;

    private String phoneNumber;

    private String address;

    @Size(max = 500, message = "Bio must not exceed 500 characters")
    private String bio;

    private String photo;

}

