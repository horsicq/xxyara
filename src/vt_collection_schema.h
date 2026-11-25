/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* Collection shapes from the pinned VT protobuf declarations. */
static yx_global_array yx_vt_array_string;
static yx_global_array yx_vt_array_vt_fileanalysis_BehaviourTag;
static yx_global_array yx_vt_array_vt_fileanalysis_DnsLookup;
static yx_global_array yx_vt_array_vt_fileanalysis_DroppedFile;
static yx_global_array yx_vt_array_vt_fileanalysis_ExtractedPayload;
static yx_global_array yx_vt_array_vt_fileanalysis_FileCopy;
static yx_global_array yx_vt_array_vt_fileanalysis_HttpConversation;
static yx_global_array yx_vt_array_vt_fileanalysis_IpTraffic;
static yx_global_array yx_vt_array_vt_fileanalysis_KeyValue;
static yx_global_array yx_vt_array_vt_fileanalysis_MalwareBehaviorCatalog;
static yx_global_array yx_vt_array_vt_fileanalysis_MitreAttackTechnique;
static yx_global_array yx_vt_array_vt_fileanalysis_PermissionCheck;
static yx_global_array yx_vt_array_vt_fileanalysis_ProcessItem;
static yx_global_array yx_vt_array_vt_fileanalysis_SignatureMatch;
static yx_global_array yx_vt_array_vt_fileanalysis_Sms;
static yx_global_array yx_vt_array_vt_fileanalysis_SmtpConversation;
static yx_global_array yx_vt_array_vt_fileanalysis_TLS;
static yx_global_array yx_vt_array_vt_fileanalysis_VerdictTag;
static yx_global_array yx_vt_array_vt_net_ConsoleMessage;
static yx_global_array yx_vt_array_vt_net_DNSRecord;
static yx_global_array yx_vt_array_vt_net_ExtendedCookie;
static yx_global_array yx_vt_array_vt_net_KeyValue;
static yx_global_array yx_vt_array_vt_net_PopularityRank;
static yx_global_array yx_vt_array_vt_net_ResourceFileMetadata;
static yx_global_array yx_vt_array_vt_net_SSLCertificate;
static yx_global_array yx_vt_array_vt_net_Tracker;
static yx_global_array yx_vt_array_vt_net_URLResource;
static yx_global_array yx_vt_array_vt_net_WebTechnology;
static yx_global_array yx_vt_array_vt_sigma_SigmaMatch;
static yx_global_array yx_vt_array_vt_sigma_SigmaMatchContext;
static yx_global_array yx_vt_array_vt_tools_net_analysis_CrowdSourcedIdsResults;
static yx_global_field yx_vt_array_vt_fileanalysis_DnsLookup_fields[] = {
    {.name = "hostname", .type = YX_GLOBAL_STR},
    {.name = "resolved_ips", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "txt_records", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
};
static yx_global_object yx_vt_array_vt_fileanalysis_DnsLookup_object = {yx_vt_array_vt_fileanalysis_DnsLookup_fields, 3};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_DnsLookup_item = {.object = &yx_vt_array_vt_fileanalysis_DnsLookup_object};
static yx_global_field yx_vt_array_vt_fileanalysis_DroppedFile_fields[] = {
    {.name = "path", .type = YX_GLOBAL_STR},         {.name = "sha256", .type = YX_GLOBAL_STR},       {.name = "type", .type = YX_GLOBAL_INT},
    {.name = "download_url", .type = YX_GLOBAL_STR}, {.name = "process_name", .type = YX_GLOBAL_STR}, {.name = "process_id", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_fileanalysis_DroppedFile_object = {yx_vt_array_vt_fileanalysis_DroppedFile_fields, 6};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_DroppedFile_item = {.object = &yx_vt_array_vt_fileanalysis_DroppedFile_object};
static yx_global_field yx_vt_array_vt_fileanalysis_ExtractedPayload_fields[] = {
    {.name = "sha256", .type = YX_GLOBAL_STR},          {.name = "type", .type = YX_GLOBAL_INT},         {.name = "size", .type = YX_GLOBAL_INT},
    {.name = "payload_type", .type = YX_GLOBAL_STR},    {.name = "process_name", .type = YX_GLOBAL_STR}, {.name = "timestamp.seconds", .type = YX_GLOBAL_INT},
    {.name = "timestamp.nanos", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_vt_array_vt_fileanalysis_ExtractedPayload_object = {yx_vt_array_vt_fileanalysis_ExtractedPayload_fields, 7};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_ExtractedPayload_item = {.object = &yx_vt_array_vt_fileanalysis_ExtractedPayload_object};
static yx_global_field yx_vt_array_vt_fileanalysis_FileCopy_fields[] = {
    {.name = "source", .type = YX_GLOBAL_STR},
    {.name = "destination", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_fileanalysis_FileCopy_object = {yx_vt_array_vt_fileanalysis_FileCopy_fields, 2};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_FileCopy_item = {.object = &yx_vt_array_vt_fileanalysis_FileCopy_object};
static yx_global_field yx_vt_array_vt_fileanalysis_HttpConversation_fields[] = {
    {.name = "url", .type = YX_GLOBAL_STR},
    {.name = "request_method", .type = YX_GLOBAL_INT},
    {.name = "response_status_code", .type = YX_GLOBAL_INT},
    {.name = "response_body_filetype", .type = YX_GLOBAL_INT},
    {.name = "response_body_first_ten_bytes", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_fileanalysis_HttpConversation_object = {yx_vt_array_vt_fileanalysis_HttpConversation_fields, 5};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_HttpConversation_item = {.object = &yx_vt_array_vt_fileanalysis_HttpConversation_object};
static yx_global_field yx_vt_array_vt_fileanalysis_IpTraffic_fields[] = {
    {.name = "destination_ip", .type = YX_GLOBAL_STR},           {.name = "destination_port", .type = YX_GLOBAL_INT},
    {.name = "transport_layer_protocol", .type = YX_GLOBAL_INT}, {.name = "destination_ip_asn", .type = YX_GLOBAL_INT},
    {.name = "destination_ip_as_int", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_vt_array_vt_fileanalysis_IpTraffic_object = {yx_vt_array_vt_fileanalysis_IpTraffic_fields, 5};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_IpTraffic_item = {.object = &yx_vt_array_vt_fileanalysis_IpTraffic_object};
static yx_global_field yx_vt_array_vt_fileanalysis_KeyValue_fields[] = {
    {.name = "key", .type = YX_GLOBAL_STR},
    {.name = "value", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_fileanalysis_KeyValue_object = {yx_vt_array_vt_fileanalysis_KeyValue_fields, 2};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_KeyValue_item = {.object = &yx_vt_array_vt_fileanalysis_KeyValue_object};
static yx_global_field yx_vt_array_vt_fileanalysis_MalwareBehaviorCatalog_fields[] = {
    {.name = "id", .type = YX_GLOBAL_STR},
    {.name = "objective", .type = YX_GLOBAL_STR},
    {.name = "behavior", .type = YX_GLOBAL_STR},
    {.name = "method", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_fileanalysis_MalwareBehaviorCatalog_object = {yx_vt_array_vt_fileanalysis_MalwareBehaviorCatalog_fields, 4};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_MalwareBehaviorCatalog_item = {.object = &yx_vt_array_vt_fileanalysis_MalwareBehaviorCatalog_object};
static yx_global_field yx_vt_array_vt_fileanalysis_MitreAttackTechnique_fields[] = {
    {.name = "id", .type = YX_GLOBAL_STR},
    {.name = "severity", .type = YX_GLOBAL_INT},
    {.name = "signature_description", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_fileanalysis_MitreAttackTechnique_object = {yx_vt_array_vt_fileanalysis_MitreAttackTechnique_fields, 3};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_MitreAttackTechnique_item = {.object = &yx_vt_array_vt_fileanalysis_MitreAttackTechnique_object};
static yx_global_field yx_vt_array_vt_fileanalysis_PermissionCheck_fields[] = {
    {.name = "permission", .type = YX_GLOBAL_STR},
    {.name = "owner", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_fileanalysis_PermissionCheck_object = {yx_vt_array_vt_fileanalysis_PermissionCheck_fields, 2};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_PermissionCheck_item = {.object = &yx_vt_array_vt_fileanalysis_PermissionCheck_object};
static yx_global_field yx_vt_array_vt_fileanalysis_ProcessItem_fields[] = {
    {.name = "process_id", .type = YX_GLOBAL_STR},
    {.name = "parent_process_id", .type = YX_GLOBAL_STR},
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "parent_name", .type = YX_GLOBAL_STR},
    {.name = "start_time", .type = YX_GLOBAL_INT},
    {.name = "termination_time", .type = YX_GLOBAL_INT},
    {.name = "files_opened", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "files_written", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "files_deleted", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "files_copied", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_vt_fileanalysis_FileCopy},
};
static yx_global_object yx_vt_array_vt_fileanalysis_ProcessItem_object = {yx_vt_array_vt_fileanalysis_ProcessItem_fields, 10};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_ProcessItem_item = {.object = &yx_vt_array_vt_fileanalysis_ProcessItem_object};
static yx_global_field yx_vt_array_vt_fileanalysis_SignatureMatch_fields[] = {
    {.name = "id", .type = YX_GLOBAL_STR},
    {.name = "format", .type = YX_GLOBAL_INT},
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "description", .type = YX_GLOBAL_STR},
    {.name = "authors", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "events", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "match_data", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "rule_src", .type = YX_GLOBAL_STR},
    {.name = "severity", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_vt_array_vt_fileanalysis_SignatureMatch_object = {yx_vt_array_vt_fileanalysis_SignatureMatch_fields, 9};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_SignatureMatch_item = {.object = &yx_vt_array_vt_fileanalysis_SignatureMatch_object};
static yx_global_field yx_vt_array_vt_fileanalysis_Sms_fields[] = {
    {.name = "destination", .type = YX_GLOBAL_STR},
    {.name = "body", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_fileanalysis_Sms_object = {yx_vt_array_vt_fileanalysis_Sms_fields, 2};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_Sms_item = {.object = &yx_vt_array_vt_fileanalysis_Sms_object};
static yx_global_field yx_vt_array_vt_fileanalysis_SmtpConversation_fields[] = {
    {.name = "hostname", .type = YX_GLOBAL_STR},
    {.name = "destination_ip", .type = YX_GLOBAL_STR},
    {.name = "destination_port", .type = YX_GLOBAL_INT},
    {.name = "smtp_from", .type = YX_GLOBAL_STR},
    {.name = "smtp_to", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "message_from", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "message_to", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "message_cc", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "message_bcc", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "timestamp", .type = YX_GLOBAL_STR},
    {.name = "subject", .type = YX_GLOBAL_STR},
    {.name = "html_body", .type = YX_GLOBAL_STR},
    {.name = "txt_body", .type = YX_GLOBAL_STR},
    {.name = "auth_user", .type = YX_GLOBAL_STR},
    {.name = "auth_pass", .type = YX_GLOBAL_STR},
    {.name = "headers", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_vt_fileanalysis_KeyValue},
    {.name = "attachments", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_vt_fileanalysis_DroppedFile},
    {.name = "x_mailer", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_fileanalysis_SmtpConversation_object = {yx_vt_array_vt_fileanalysis_SmtpConversation_fields, 18};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_SmtpConversation_item = {.object = &yx_vt_array_vt_fileanalysis_SmtpConversation_object};
static yx_global_field yx_vt_array_vt_fileanalysis_TLS_fields[] = {
    {.name = "serial_number", .type = YX_GLOBAL_STR}, {.name = "thumbprint", .type = YX_GLOBAL_STR}, {.name = "version", .type = YX_GLOBAL_STR},
    {.name = "sni", .type = YX_GLOBAL_STR},           {.name = "ja3", .type = YX_GLOBAL_STR},        {.name = "ja3s", .type = YX_GLOBAL_STR},
    {.name = "ja4", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_fileanalysis_TLS_object = {yx_vt_array_vt_fileanalysis_TLS_fields, 7};
static yx_global_scalar_value yx_vt_array_vt_fileanalysis_TLS_item = {.object = &yx_vt_array_vt_fileanalysis_TLS_object};
static yx_global_field yx_vt_array_vt_net_ConsoleMessage_fields[] = {
    {.name = "content", .type = YX_GLOBAL_STR},
    {.name = "source_file", .type = YX_GLOBAL_STR},
    {.name = "level", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_vt_array_vt_net_ConsoleMessage_object = {yx_vt_array_vt_net_ConsoleMessage_fields, 3};
static yx_global_scalar_value yx_vt_array_vt_net_ConsoleMessage_item = {.object = &yx_vt_array_vt_net_ConsoleMessage_object};
static yx_global_field yx_vt_array_vt_net_DNSRecord_fields[] = {
    {.name = "type", .type = YX_GLOBAL_STR},   {.name = "dns_class", .type = YX_GLOBAL_STR}, {.name = "ttl", .type = YX_GLOBAL_INT},
    {.name = "mname", .type = YX_GLOBAL_STR},  {.name = "rname", .type = YX_GLOBAL_STR},     {.name = "priority", .type = YX_GLOBAL_INT},
    {.name = "serial", .type = YX_GLOBAL_INT}, {.name = "retry", .type = YX_GLOBAL_INT},     {.name = "refresh", .type = YX_GLOBAL_INT},
    {.name = "expire", .type = YX_GLOBAL_INT}, {.name = "minimum", .type = YX_GLOBAL_INT},   {.name = "value", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_net_DNSRecord_object = {yx_vt_array_vt_net_DNSRecord_fields, 12};
static yx_global_scalar_value yx_vt_array_vt_net_DNSRecord_item = {.object = &yx_vt_array_vt_net_DNSRecord_object};
static yx_global_field yx_vt_array_vt_net_ExtendedCookie_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},     {.name = "value", .type = YX_GLOBAL_STR},   {.name = "domain", .type = YX_GLOBAL_STR},
    {.name = "expires", .type = YX_GLOBAL_INT},  {.name = "secure", .type = YX_GLOBAL_BOOL}, {.name = "http_only", .type = YX_GLOBAL_BOOL},
    {.name = "session", .type = YX_GLOBAL_BOOL}, {.name = "size", .type = YX_GLOBAL_INT},    {.name = "priority", .type = YX_GLOBAL_INT},
};
static yx_global_object yx_vt_array_vt_net_ExtendedCookie_object = {yx_vt_array_vt_net_ExtendedCookie_fields, 9};
static yx_global_scalar_value yx_vt_array_vt_net_ExtendedCookie_item = {.object = &yx_vt_array_vt_net_ExtendedCookie_object};
static yx_global_field yx_vt_array_vt_net_KeyValue_fields[] = {
    {.name = "key", .type = YX_GLOBAL_STR},
    {.name = "values", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
};
static yx_global_object yx_vt_array_vt_net_KeyValue_object = {yx_vt_array_vt_net_KeyValue_fields, 2};
static yx_global_scalar_value yx_vt_array_vt_net_KeyValue_item = {.object = &yx_vt_array_vt_net_KeyValue_object};
static yx_global_field yx_vt_array_vt_net_PopularityRank_fields[] = {
    {.name = "position", .type = YX_GLOBAL_INT},
    {.name = "ingestion_time", .type = YX_GLOBAL_INT},
    {.name = "rank", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_net_PopularityRank_object = {yx_vt_array_vt_net_PopularityRank_fields, 3};
static yx_global_scalar_value yx_vt_array_vt_net_PopularityRank_item = {.object = &yx_vt_array_vt_net_PopularityRank_object};
static yx_global_field yx_vt_array_vt_net_ResourceFileMetadata_fields[] = {
    {.name = "sha256", .type = YX_GLOBAL_STR},
    {.name = "analysis_stats.malicious", .type = YX_GLOBAL_INT},
    {.name = "analysis_stats.suspicious", .type = YX_GLOBAL_INT},
    {.name = "analysis_stats.undetected", .type = YX_GLOBAL_INT},
    {.name = "analysis_stats.harmless", .type = YX_GLOBAL_INT},
    {.name = "analysis_stats.failure", .type = YX_GLOBAL_INT},
    {.name = "analysis_stats.type_unsupported", .type = YX_GLOBAL_INT},
    {.name = "file_type", .type = YX_GLOBAL_INT},
    {.name = "new_for_url", .type = YX_GLOBAL_BOOL},
};
static yx_global_object yx_vt_array_vt_net_ResourceFileMetadata_object = {yx_vt_array_vt_net_ResourceFileMetadata_fields, 9};
static yx_global_scalar_value yx_vt_array_vt_net_ResourceFileMetadata_item = {.object = &yx_vt_array_vt_net_ResourceFileMetadata_object};
static yx_global_field yx_vt_array_vt_net_SSLCertificate_fields[] = {
    {.name = "thumbprint", .type = YX_GLOBAL_STR},
    {.name = "subject.common_name", .type = YX_GLOBAL_STR},
    {.name = "subject.country", .type = YX_GLOBAL_STR},
    {.name = "subject.organization", .type = YX_GLOBAL_STR},
    {.name = "subject.organizational_unit", .type = YX_GLOBAL_STR},
    {.name = "subject.locality", .type = YX_GLOBAL_STR},
    {.name = "subject.state", .type = YX_GLOBAL_STR},
    {.name = "subject.alternative_names", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "subject.street_address", .type = YX_GLOBAL_STR},
    {.name = "subject.postal_code", .type = YX_GLOBAL_STR},
    {.name = "validity.not_after", .type = YX_GLOBAL_INT},
    {.name = "validity.not_before", .type = YX_GLOBAL_INT},
    {.name = "subject_alternative_name", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "signature", .type = YX_GLOBAL_STR},
    {.name = "serial_number", .type = YX_GLOBAL_STR},
    {.name = "issuer.common_name", .type = YX_GLOBAL_STR},
    {.name = "issuer.country", .type = YX_GLOBAL_STR},
    {.name = "issuer.organization", .type = YX_GLOBAL_STR},
    {.name = "issuer.organizational_unit", .type = YX_GLOBAL_STR},
    {.name = "issuer.locality", .type = YX_GLOBAL_STR},
    {.name = "issuer.state", .type = YX_GLOBAL_STR},
    {.name = "issuer.alternative_names", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "issuer.street_address", .type = YX_GLOBAL_STR},
    {.name = "issuer.postal_code", .type = YX_GLOBAL_STR},
    {.name = "host", .type = YX_GLOBAL_STR},
    {.name = "version", .type = YX_GLOBAL_STR},
    {.name = "algorithm", .type = YX_GLOBAL_STR},
    {.name = "signature_algorithm", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_net_SSLCertificate_object = {yx_vt_array_vt_net_SSLCertificate_fields, 28};
static yx_global_scalar_value yx_vt_array_vt_net_SSLCertificate_item = {.object = &yx_vt_array_vt_net_SSLCertificate_object};
static yx_global_field yx_vt_array_vt_net_Tracker_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "id", .type = YX_GLOBAL_STR},
    {.name = "url", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_net_Tracker_object = {yx_vt_array_vt_net_Tracker_fields, 3};
static yx_global_scalar_value yx_vt_array_vt_net_Tracker_item = {.object = &yx_vt_array_vt_net_Tracker_object};
static yx_global_field yx_vt_array_vt_net_URLResource_fields[] = {
    {.name = "url", .type = YX_GLOBAL_STR},
    {.name = "method", .type = YX_GLOBAL_INT},
    {.name = "sha256", .type = YX_GLOBAL_STR},
    {.name = "response_code", .type = YX_GLOBAL_INT},
    {.name = "serving_ip_address", .type = YX_GLOBAL_STR},
    {.name = "content_length", .type = YX_GLOBAL_INT},
    {.name = "reverse_dns", .type = YX_GLOBAL_STR},
    {.name = "type", .type = YX_GLOBAL_INT},
    {.name = "browser_type", .type = YX_GLOBAL_INT},
    {.name = "net_error", .type = YX_GLOBAL_INT},
    {.name = "redirects", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
};
static yx_global_object yx_vt_array_vt_net_URLResource_object = {yx_vt_array_vt_net_URLResource_fields, 11};
static yx_global_scalar_value yx_vt_array_vt_net_URLResource_item = {.object = &yx_vt_array_vt_net_URLResource_object};
static yx_global_field yx_vt_array_vt_net_WebTechnology_fields[] = {
    {.name = "name", .type = YX_GLOBAL_STR},
    {.name = "version", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_net_WebTechnology_object = {yx_vt_array_vt_net_WebTechnology_fields, 2};
static yx_global_scalar_value yx_vt_array_vt_net_WebTechnology_item = {.object = &yx_vt_array_vt_net_WebTechnology_object};
static yx_global_field yx_vt_array_vt_sigma_SigmaMatch_fields[] = {
    {.name = "match_context", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_vt_sigma_SigmaMatchContext},
    {.name = "rule_level", .type = YX_GLOBAL_INT},
    {.name = "rule_id", .type = YX_GLOBAL_STR},
    {.name = "rule_source", .type = YX_GLOBAL_STR},
    {.name = "rule_title", .type = YX_GLOBAL_STR},
    {.name = "rule_description", .type = YX_GLOBAL_STR},
    {.name = "rule_author", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_sigma_SigmaMatch_object = {yx_vt_array_vt_sigma_SigmaMatch_fields, 7};
static yx_global_scalar_value yx_vt_array_vt_sigma_SigmaMatch_item = {.object = &yx_vt_array_vt_sigma_SigmaMatch_object};
static yx_global_field yx_vt_array_vt_sigma_SigmaMatchContext_fields[] = {
    {0},
};
static yx_global_object yx_vt_array_vt_sigma_SigmaMatchContext_object = {yx_vt_array_vt_sigma_SigmaMatchContext_fields, 0};
static yx_global_scalar_value yx_vt_array_vt_sigma_SigmaMatchContext_item = {.object = &yx_vt_array_vt_sigma_SigmaMatchContext_object};
static yx_global_field yx_vt_array_vt_tools_net_analysis_CrowdSourcedIdsResults_fields[] = {
    {.name = "rule_msg", .type = YX_GLOBAL_STR},
    {.name = "rule_category", .type = YX_GLOBAL_STR},
    {.name = "rule_id", .type = YX_GLOBAL_STR},
    {.name = "alert_severity", .type = YX_GLOBAL_INT},
    {.name = "rule_source", .type = YX_GLOBAL_STR},
    {.name = "alert_context.protocol", .type = YX_GLOBAL_INT},
    {.name = "alert_context.src_ip", .type = YX_GLOBAL_STR},
    {.name = "alert_context.src_port", .type = YX_GLOBAL_INT},
    {.name = "alert_context.dest_ip", .type = YX_GLOBAL_STR},
    {.name = "alert_context.dest_port", .type = YX_GLOBAL_INT},
    {.name = "alert_context.hostname", .type = YX_GLOBAL_STR},
    {.name = "alert_context.url", .type = YX_GLOBAL_STR},
    {.name = "alert_context.ja3", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "alert_context.ja3s", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "rule_url", .type = YX_GLOBAL_STR},
    {.name = "rule_references", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "tags", .type = YX_GLOBAL_ARRAY, .value.array = &yx_vt_array_string},
    {.name = "rule_raw", .type = YX_GLOBAL_STR},
};
static yx_global_object yx_vt_array_vt_tools_net_analysis_CrowdSourcedIdsResults_object = {yx_vt_array_vt_tools_net_analysis_CrowdSourcedIdsResults_fields, 18};
static yx_global_scalar_value yx_vt_array_vt_tools_net_analysis_CrowdSourcedIdsResults_item = {.object =
                                                                                                   &yx_vt_array_vt_tools_net_analysis_CrowdSourcedIdsResults_object};
static yx_global_array yx_vt_array_string = {YX_GLOBAL_STR, NULL, 0};
static yx_global_array yx_vt_array_vt_fileanalysis_BehaviourTag = {YX_GLOBAL_INT, NULL, 0};
static yx_global_array yx_vt_array_vt_fileanalysis_DnsLookup = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_DnsLookup_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_DroppedFile = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_DroppedFile_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_ExtractedPayload = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_ExtractedPayload_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_FileCopy = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_FileCopy_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_HttpConversation = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_HttpConversation_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_IpTraffic = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_IpTraffic_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_KeyValue = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_KeyValue_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_MalwareBehaviorCatalog = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_MalwareBehaviorCatalog_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_MitreAttackTechnique = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_MitreAttackTechnique_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_PermissionCheck = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_PermissionCheck_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_ProcessItem = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_ProcessItem_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_SignatureMatch = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_SignatureMatch_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_Sms = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_Sms_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_SmtpConversation = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_SmtpConversation_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_TLS = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_fileanalysis_TLS_item, 1};
static yx_global_array yx_vt_array_vt_fileanalysis_VerdictTag = {YX_GLOBAL_INT, NULL, 0};
static yx_global_array yx_vt_array_vt_net_ConsoleMessage = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_net_ConsoleMessage_item, 1};
static yx_global_array yx_vt_array_vt_net_DNSRecord = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_net_DNSRecord_item, 1};
static yx_global_array yx_vt_array_vt_net_ExtendedCookie = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_net_ExtendedCookie_item, 1};
static yx_global_array yx_vt_array_vt_net_KeyValue = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_net_KeyValue_item, 1};
static yx_global_array yx_vt_array_vt_net_PopularityRank = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_net_PopularityRank_item, 1};
static yx_global_array yx_vt_array_vt_net_ResourceFileMetadata = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_net_ResourceFileMetadata_item, 1};
static yx_global_array yx_vt_array_vt_net_SSLCertificate = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_net_SSLCertificate_item, 1};
static yx_global_array yx_vt_array_vt_net_Tracker = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_net_Tracker_item, 1};
static yx_global_array yx_vt_array_vt_net_URLResource = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_net_URLResource_item, 1};
static yx_global_array yx_vt_array_vt_net_WebTechnology = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_net_WebTechnology_item, 1};
static yx_global_array yx_vt_array_vt_sigma_SigmaMatch = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_sigma_SigmaMatch_item, 1};
static yx_global_array yx_vt_array_vt_sigma_SigmaMatchContext = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_sigma_SigmaMatchContext_item, 1};
static yx_global_array yx_vt_array_vt_tools_net_analysis_CrowdSourcedIdsResults = {YX_GLOBAL_STRUCT, &yx_vt_array_vt_tools_net_analysis_CrowdSourcedIdsResults_item, 1};
static const yx_module_array_desc yx_vt_arrays[] = {
    {"vt.metadata.tags", &yx_vt_array_string, 0},
    {"vt.metadata.file_type_tags", &yx_vt_array_string, 0},
    {"vt.metadata.malware_families", &yx_vt_array_string, 0},
    {"vt.metadata.itw.url.trackers", &yx_vt_array_vt_net_Tracker, 0},
    {"vt.metadata.itw.url.outgoing_links", &yx_vt_array_string, 0},
    {"vt.metadata.itw.url.redirects", &yx_vt_array_string, 0},
    {"vt.metadata.itw.url.html_meta_tags", &yx_vt_array_vt_net_KeyValue, 0},
    {"vt.metadata.itw.url.html_meta_tags.values", &yx_vt_array_string, 1},
    {"vt.metadata.itw.url.tags", &yx_vt_array_string, 0},
    {"vt.metadata.itw.url.embedded_resources", &yx_vt_array_vt_net_ResourceFileMetadata, 0},
    {"vt.metadata.itw.url.resources", &yx_vt_array_vt_net_URLResource, 0},
    {"vt.metadata.itw.url.resources.redirects", &yx_vt_array_string, 1},
    {"vt.metadata.itw.url.cookies_extended", &yx_vt_array_vt_net_ExtendedCookie, 0},
    {"vt.metadata.itw.url.console_messages", &yx_vt_array_vt_net_ConsoleMessage, 0},
    {"vt.metadata.itw.url.web_technologies", &yx_vt_array_vt_net_WebTechnology, 0},
    {"vt.metadata.itw.url.tls", &yx_vt_array_vt_net_SSLCertificate, 0},
    {"vt.metadata.itw.url.tls.subject.alternative_names", &yx_vt_array_string, 1},
    {"vt.metadata.itw.url.tls.subject_alternative_name", &yx_vt_array_string, 1},
    {"vt.metadata.itw.url.tls.issuer.alternative_names", &yx_vt_array_string, 1},
    {"vt.metadata.itw.ip.https_certificate.subject.alternative_names", &yx_vt_array_string, 0},
    {"vt.metadata.itw.ip.https_certificate.subject_alternative_name", &yx_vt_array_string, 0},
    {"vt.metadata.itw.ip.https_certificate.issuer.alternative_names", &yx_vt_array_string, 0},
    {"vt.metadata.itw.ip.tags", &yx_vt_array_string, 0},
    {"vt.metadata.itw.domain.https_certificate.subject.alternative_names", &yx_vt_array_string, 0},
    {"vt.metadata.itw.domain.https_certificate.subject_alternative_name", &yx_vt_array_string, 0},
    {"vt.metadata.itw.domain.https_certificate.issuer.alternative_names", &yx_vt_array_string, 0},
    {"vt.metadata.itw.domain.dns_records", &yx_vt_array_vt_net_DNSRecord, 0},
    {"vt.metadata.itw.domain.tags", &yx_vt_array_string, 0},
    {"vt.metadata.itw.domain.popularity_ranks", &yx_vt_array_vt_net_PopularityRank, 0},
    {"vt.metadata.itw.domain.root_popularity_ranks", &yx_vt_array_vt_net_PopularityRank, 0},
    {"vt.behaviour.files_opened", &yx_vt_array_string, 0},
    {"vt.behaviour.files_written", &yx_vt_array_string, 0},
    {"vt.behaviour.files_deleted", &yx_vt_array_string, 0},
    {"vt.behaviour.files_copied", &yx_vt_array_vt_fileanalysis_FileCopy, 0},
    {"vt.behaviour.files_attribute_changed", &yx_vt_array_string, 0},
    {"vt.behaviour.files_dropped", &yx_vt_array_vt_fileanalysis_DroppedFile, 0},
    {"vt.behaviour.payloads_extracted", &yx_vt_array_vt_fileanalysis_ExtractedPayload, 0},
    {"vt.behaviour.processes_list", &yx_vt_array_vt_fileanalysis_ProcessItem, 0},
    {"vt.behaviour.processes_list.files_opened", &yx_vt_array_string, 1},
    {"vt.behaviour.processes_list.files_written", &yx_vt_array_string, 1},
    {"vt.behaviour.processes_list.files_deleted", &yx_vt_array_string, 1},
    {"vt.behaviour.processes_list.files_copied", &yx_vt_array_vt_fileanalysis_FileCopy, 1},
    {"vt.behaviour.processes_created", &yx_vt_array_string, 0},
    {"vt.behaviour.processes_terminated", &yx_vt_array_string, 0},
    {"vt.behaviour.processes_killed", &yx_vt_array_string, 0},
    {"vt.behaviour.processes_injected", &yx_vt_array_string, 0},
    {"vt.behaviour.command_executions", &yx_vt_array_string, 0},
    {"vt.behaviour.services_opened", &yx_vt_array_string, 0},
    {"vt.behaviour.services_created", &yx_vt_array_string, 0},
    {"vt.behaviour.services_started", &yx_vt_array_string, 0},
    {"vt.behaviour.services_stopped", &yx_vt_array_string, 0},
    {"vt.behaviour.services_deleted", &yx_vt_array_string, 0},
    {"vt.behaviour.services_bound", &yx_vt_array_string, 0},
    {"vt.behaviour.windows_searched", &yx_vt_array_string, 0},
    {"vt.behaviour.windows_hidden", &yx_vt_array_string, 0},
    {"vt.behaviour.permissions_checked", &yx_vt_array_vt_fileanalysis_PermissionCheck, 0},
    {"vt.behaviour.permissions_requested", &yx_vt_array_string, 0},
    {"vt.behaviour.mutexes_opened", &yx_vt_array_string, 0},
    {"vt.behaviour.mutexes_created", &yx_vt_array_string, 0},
    {"vt.behaviour.signals_observed", &yx_vt_array_string, 0},
    {"vt.behaviour.signals_hooked", &yx_vt_array_string, 0},
    {"vt.behaviour.modules_loaded", &yx_vt_array_string, 0},
    {"vt.behaviour.calls_highlighted", &yx_vt_array_string, 0},
    {"vt.behaviour.invokes", &yx_vt_array_string, 0},
    {"vt.behaviour.crypto_algorithms_observed", &yx_vt_array_string, 0},
    {"vt.behaviour.crypto_keys", &yx_vt_array_string, 0},
    {"vt.behaviour.crypto_plain_text", &yx_vt_array_string, 0},
    {"vt.behaviour.encoding_algorithms_observed", &yx_vt_array_string, 0},
    {"vt.behaviour.text_decoded", &yx_vt_array_string, 0},
    {"vt.behaviour.text_highlighted", &yx_vt_array_string, 0},
    {"vt.behaviour.traits", &yx_vt_array_vt_fileanalysis_BehaviourTag, 0},
    {"vt.behaviour.databases_opened", &yx_vt_array_string, 0},
    {"vt.behaviour.databases_deleted", &yx_vt_array_string, 0},
    {"vt.behaviour.registry_keys_opened", &yx_vt_array_string, 0},
    {"vt.behaviour.registry_keys_set", &yx_vt_array_vt_fileanalysis_KeyValue, 0},
    {"vt.behaviour.registry_keys_deleted", &yx_vt_array_string, 0},
    {"vt.behaviour.system_property_lookups", &yx_vt_array_string, 0},
    {"vt.behaviour.system_property_sets", &yx_vt_array_vt_fileanalysis_KeyValue, 0},
    {"vt.behaviour.shared_preferences_lookups", &yx_vt_array_string, 0},
    {"vt.behaviour.shared_preferences_sets", &yx_vt_array_vt_fileanalysis_KeyValue, 0},
    {"vt.behaviour.content_model_observers", &yx_vt_array_string, 0},
    {"vt.behaviour.content_model_sets", &yx_vt_array_vt_fileanalysis_KeyValue, 0},
    {"vt.behaviour.activities_started", &yx_vt_array_string, 0},
    {"vt.behaviour.http_conversations", &yx_vt_array_vt_fileanalysis_HttpConversation, 0},
    {"vt.behaviour.dns_lookups", &yx_vt_array_vt_fileanalysis_DnsLookup, 0},
    {"vt.behaviour.dns_lookups.resolved_ips", &yx_vt_array_string, 1},
    {"vt.behaviour.dns_lookups.txt_records", &yx_vt_array_string, 1},
    {"vt.behaviour.ip_traffic", &yx_vt_array_vt_fileanalysis_IpTraffic, 0},
    {"vt.behaviour.sms_sent", &yx_vt_array_vt_fileanalysis_Sms, 0},
    {"vt.behaviour.verdicts", &yx_vt_array_vt_fileanalysis_VerdictTag, 0},
    {"vt.behaviour.verdict_labels", &yx_vt_array_string, 0},
    {"vt.behaviour.ja3_digests", &yx_vt_array_string, 0},
    {"vt.behaviour.memory_pattern_ips", &yx_vt_array_string, 0},
    {"vt.behaviour.memory_pattern_domains", &yx_vt_array_string, 0},
    {"vt.behaviour.memory_pattern_urls", &yx_vt_array_string, 0},
    {"vt.behaviour.smtp_conversations", &yx_vt_array_vt_fileanalysis_SmtpConversation, 0},
    {"vt.behaviour.smtp_conversations.smtp_to", &yx_vt_array_string, 1},
    {"vt.behaviour.smtp_conversations.message_from", &yx_vt_array_string, 1},
    {"vt.behaviour.smtp_conversations.message_to", &yx_vt_array_string, 1},
    {"vt.behaviour.smtp_conversations.message_cc", &yx_vt_array_string, 1},
    {"vt.behaviour.smtp_conversations.message_bcc", &yx_vt_array_string, 1},
    {"vt.behaviour.smtp_conversations.headers", &yx_vt_array_vt_fileanalysis_KeyValue, 1},
    {"vt.behaviour.smtp_conversations.attachments", &yx_vt_array_vt_fileanalysis_DroppedFile, 1},
    {"vt.behaviour.ids_alerts", &yx_vt_array_vt_tools_net_analysis_CrowdSourcedIdsResults, 0},
    {"vt.behaviour.ids_alerts.alert_context.ja3", &yx_vt_array_string, 1},
    {"vt.behaviour.ids_alerts.alert_context.ja3s", &yx_vt_array_string, 1},
    {"vt.behaviour.ids_alerts.rule_references", &yx_vt_array_string, 1},
    {"vt.behaviour.ids_alerts.tags", &yx_vt_array_string, 1},
    {"vt.behaviour.tls", &yx_vt_array_vt_fileanalysis_TLS, 0},
    {"vt.behaviour.mitre_attack_techniques", &yx_vt_array_vt_fileanalysis_MitreAttackTechnique, 0},
    {"vt.behaviour.sigma_analysis_results", &yx_vt_array_vt_sigma_SigmaMatch, 0},
    {"vt.behaviour.sigma_analysis_results.match_context", &yx_vt_array_vt_sigma_SigmaMatchContext, 1},
    {"vt.behaviour.signature_matches", &yx_vt_array_vt_fileanalysis_SignatureMatch, 0},
    {"vt.behaviour.signature_matches.authors", &yx_vt_array_string, 1},
    {"vt.behaviour.signature_matches.events", &yx_vt_array_string, 1},
    {"vt.behaviour.signature_matches.match_data", &yx_vt_array_string, 1},
    {"vt.behaviour.mbc", &yx_vt_array_vt_fileanalysis_MalwareBehaviorCatalog, 0},
    {"vt.net.url.trackers", &yx_vt_array_vt_net_Tracker, 0},
    {"vt.net.url.outgoing_links", &yx_vt_array_string, 0},
    {"vt.net.url.redirects", &yx_vt_array_string, 0},
    {"vt.net.url.html_meta_tags", &yx_vt_array_vt_net_KeyValue, 0},
    {"vt.net.url.html_meta_tags.values", &yx_vt_array_string, 1},
    {"vt.net.url.tags", &yx_vt_array_string, 0},
    {"vt.net.url.embedded_resources", &yx_vt_array_vt_net_ResourceFileMetadata, 0},
    {"vt.net.url.resources", &yx_vt_array_vt_net_URLResource, 0},
    {"vt.net.url.resources.redirects", &yx_vt_array_string, 1},
    {"vt.net.url.cookies_extended", &yx_vt_array_vt_net_ExtendedCookie, 0},
    {"vt.net.url.console_messages", &yx_vt_array_vt_net_ConsoleMessage, 0},
    {"vt.net.url.web_technologies", &yx_vt_array_vt_net_WebTechnology, 0},
    {"vt.net.url.tls", &yx_vt_array_vt_net_SSLCertificate, 0},
    {"vt.net.url.tls.subject.alternative_names", &yx_vt_array_string, 1},
    {"vt.net.url.tls.subject_alternative_name", &yx_vt_array_string, 1},
    {"vt.net.url.tls.issuer.alternative_names", &yx_vt_array_string, 1},
    {"vt.net.ip.https_certificate.subject.alternative_names", &yx_vt_array_string, 0},
    {"vt.net.ip.https_certificate.subject_alternative_name", &yx_vt_array_string, 0},
    {"vt.net.ip.https_certificate.issuer.alternative_names", &yx_vt_array_string, 0},
    {"vt.net.ip.tags", &yx_vt_array_string, 0},
    {"vt.net.domain.https_certificate.subject.alternative_names", &yx_vt_array_string, 0},
    {"vt.net.domain.https_certificate.subject_alternative_name", &yx_vt_array_string, 0},
    {"vt.net.domain.https_certificate.issuer.alternative_names", &yx_vt_array_string, 0},
    {"vt.net.domain.dns_records", &yx_vt_array_vt_net_DNSRecord, 0},
    {"vt.net.domain.tags", &yx_vt_array_string, 0},
    {"vt.net.domain.popularity_ranks", &yx_vt_array_vt_net_PopularityRank, 0},
    {"vt.net.domain.root_popularity_ranks", &yx_vt_array_vt_net_PopularityRank, 0},
};
