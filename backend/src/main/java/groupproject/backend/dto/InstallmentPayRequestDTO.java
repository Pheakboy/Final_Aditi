package groupproject.backend.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.UUID;

@Data
public class InstallmentPayRequestDTO {
    @NotNull(message = "Installment ID is required")
    private UUID installmentId;
}
