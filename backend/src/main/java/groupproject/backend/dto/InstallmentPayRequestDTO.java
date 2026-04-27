package groupproject.backend.dto;

import lombok.Data;

import java.util.UUID;

@Data
public class InstallmentPayRequestDTO {
    private UUID installmentId;
}
