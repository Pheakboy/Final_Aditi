package groupproject.backend.service;

import groupproject.backend.model.AuditLog;

import java.util.List;

public interface AuditLogService {
    void log(String action, String performedBy, String details);
    void log(String action, String performedBy, String details, String targetId, String targetType, String ipAddress);
    List<AuditLog> getAll();
}
