package groupproject.backend.dto;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

import groupproject.backend.model.enums.TransactionType;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TransactionResponseDTO {
    private UUID id;
    private TransactionType type;
    private BigDecimal amount;
    private String description;
    private LocalDate transactionDate;
    private LocalDateTime createdAt;
}
