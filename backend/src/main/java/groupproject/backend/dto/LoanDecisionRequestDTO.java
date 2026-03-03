package groupproject.backend.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class LoanDecisionRequestDTO {
    @NotNull(message = "Decision is required (APPROVED or REJECTED)")
    private String decision; // "APPROVED" or "REJECTED"

    private String note;
}
