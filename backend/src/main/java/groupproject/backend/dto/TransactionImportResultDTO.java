package groupproject.backend.dto;

import lombok.Data;

import java.util.List;

@Data
public class TransactionImportResultDTO {
    private int imported;
    private int skipped;
    private List<String> errors;
}
