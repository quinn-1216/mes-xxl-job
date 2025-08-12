package com.xxl.job.admin.dao;

import com.xxl.job.admin.core.model.XxlJobAuditLog;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface XxlJobAuditLogDao {
    int save(XxlJobAuditLog log);

    List<XxlJobAuditLog> findByJobId(@Param("jobId") int jobId);
}

