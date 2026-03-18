package groupproject.backend.service;

import groupproject.backend.dto.TransactionImportResultDTO;
import groupproject.backend.response.ApiResponse;
import org.springframework.security.core.Authentication;
import org.springframework.web.multipart.MultipartFile;

public interface TransactionImportService {
    ApiResponse<TransactionImportResultDTO> importFromFile(Authentication authentication, MultipartFile file);
}
