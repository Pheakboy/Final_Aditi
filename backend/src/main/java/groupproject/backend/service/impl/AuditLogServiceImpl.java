package groupproject.backend.service.impl;

import groupproject.backend.model.AuditLog;
import groupproject.backend.repository.AuditLogRepository;
import groupproject.backend.service.AuditLogService;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuditLogServiceImpl implements AuditLogService {

    private final AuditLogRepository auditLogRepository;

    public AuditLogServiceImpl(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Override
    public void log(String action, String performedBy, String details) {
        log(action, performedBy, details, null, null, null);
    }

    @Override
    public void log(String action, String performedBy, String details,
                    String targetId, String targetType, String ipAddress) {
        AuditLog entry = AuditLog.builder()
                .action(action)
                .performedBy(performedBy)
                .details(details)
                .targetId(targetId)
                .targetType(targetType)
                .ipAddress(ipAddress)
                .build();
        auditLogRepository.save(entry);
    }

    @Override
    public List<AuditLog> getAll() {
        return auditLogRepository.findAllByOrderByTimestampDesc();
    }
}
