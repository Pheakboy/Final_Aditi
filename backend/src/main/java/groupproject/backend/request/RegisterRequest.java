package groupproject.backend.request;

import org.springframework.web.multipart.MultipartFile;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {

    @NotBlank
    private String username;

    @Email
    @NotBlank
    private String email;

    private String phoneNumber;

    private String address;

    private String bio;

    private MultipartFile photo;

    @NotBlank
    @Size(min=6)
    private String password;

    @NotBlank
    private String confirmPassword;
}
