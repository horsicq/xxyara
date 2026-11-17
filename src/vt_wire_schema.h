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


/* Wire descriptors from the pinned VT protobuf declarations. */
static const yx_vt_wire_field yx_vt_wire_google_protobuf_Timestamp[] = {
    {"seconds", 1, YX_VTW_INT64, 0, 0},
    {"nanos", 2, YX_VTW_INT32, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_MapEntry[] = {
    {"key", 1, YX_VTW_STRING, 0, 0},
    {"value", 2, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_analysis_AnalysisStats[] = {
    {"malicious", 1, YX_VTW_INT32, 0, 0},
    {"suspicious", 2, YX_VTW_INT32, 0, 0},
    {"undetected", 3, YX_VTW_INT32, 0, 0},
    {"harmless", 4, YX_VTW_INT32, 0, 0},
    {"failure", 5, YX_VTW_INT32, 0, 0},
    {"type_unsupported", 6, YX_VTW_INT32, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_BehaviourSummary[] = {
    {"files_opened", 1, YX_VTW_STRING, 0, 1},
    {"files_written", 2, YX_VTW_STRING, 0, 1},
    {"files_deleted", 3, YX_VTW_STRING, 0, 1},
    {"files_copied", 4, YX_VTW_MESSAGE, 7, 1},
    {"files_attribute_changed", 5, YX_VTW_STRING, 0, 1},
    {"files_dropped", 6, YX_VTW_MESSAGE, 5, 1},
    {"payloads_extracted", 84, YX_VTW_MESSAGE, 6, 1},
    {"hosts_file", 7, YX_VTW_STRING, 0, 0},
    {"processes_list", 75, YX_VTW_MESSAGE, 14, 1},
    {"processes_created", 9, YX_VTW_STRING, 0, 1},
    {"processes_terminated", 10, YX_VTW_STRING, 0, 1},
    {"processes_killed", 11, YX_VTW_STRING, 0, 1},
    {"processes_injected", 12, YX_VTW_STRING, 0, 1},
    {"command_executions", 13, YX_VTW_STRING, 0, 1},
    {"services_opened", 14, YX_VTW_STRING, 0, 1},
    {"services_created", 15, YX_VTW_STRING, 0, 1},
    {"services_started", 16, YX_VTW_STRING, 0, 1},
    {"services_stopped", 17, YX_VTW_STRING, 0, 1},
    {"services_deleted", 18, YX_VTW_STRING, 0, 1},
    {"services_bound", 19, YX_VTW_STRING, 0, 1},
    {"windows_searched", 20, YX_VTW_STRING, 0, 1},
    {"windows_hidden", 21, YX_VTW_STRING, 0, 1},
    {"permissions_checked", 22, YX_VTW_MESSAGE, 13, 1},
    {"permissions_requested", 23, YX_VTW_STRING, 0, 1},
    {"mutexes_opened", 24, YX_VTW_STRING, 0, 1},
    {"mutexes_created", 25, YX_VTW_STRING, 0, 1},
    {"signals_observed", 26, YX_VTW_STRING, 0, 1},
    {"signals_hooked", 27, YX_VTW_STRING, 0, 1},
    {"modules_loaded", 28, YX_VTW_STRING, 0, 1},
    {"calls_highlighted", 29, YX_VTW_STRING, 0, 1},
    {"invokes", 30, YX_VTW_STRING, 0, 1},
    {"crypto_algorithms_observed", 31, YX_VTW_STRING, 0, 1},
    {"crypto_keys", 32, YX_VTW_STRING, 0, 1},
    {"crypto_plain_text", 33, YX_VTW_STRING, 0, 1},
    {"encoding_algorithms_observed", 34, YX_VTW_STRING, 0, 1},
    {"text_decoded", 35, YX_VTW_STRING, 0, 1},
    {"text_highlighted", 36, YX_VTW_STRING, 0, 1},
    {"traits", 37, YX_VTW_INT32, 0, 1},
    {"databases_opened", 55, YX_VTW_STRING, 0, 1},
    {"databases_deleted", 56, YX_VTW_STRING, 0, 1},
    {"registry_keys_opened", 38, YX_VTW_STRING, 0, 1},
    {"registry_keys_set", 39, YX_VTW_MESSAGE, 10, 1},
    {"registry_keys_deleted", 40, YX_VTW_STRING, 0, 1},
    {"system_property_lookups", 41, YX_VTW_STRING, 0, 1},
    {"system_property_sets", 42, YX_VTW_MESSAGE, 10, 1},
    {"shared_preferences_lookups", 43, YX_VTW_STRING, 0, 1},
    {"shared_preferences_sets", 44, YX_VTW_MESSAGE, 10, 1},
    {"content_model_observers", 45, YX_VTW_STRING, 0, 1},
    {"content_model_sets", 46, YX_VTW_MESSAGE, 10, 1},
    {"activities_started", 47, YX_VTW_STRING, 0, 1},
    {"http_conversations", 48, YX_VTW_MESSAGE, 8, 1},
    {"dns_lookups", 49, YX_VTW_MESSAGE, 4, 1},
    {"ip_traffic", 50, YX_VTW_MESSAGE, 9, 1},
    {"sms_sent", 51, YX_VTW_MESSAGE, 16, 1},
    {"verdicts", 52, YX_VTW_INT32, 0, 1},
    {"verdict_confidence", 61, YX_VTW_INT32, 0, 0},
    {"verdict_labels", 65, YX_VTW_STRING, 0, 1},
    {"ja3_digests", 57, YX_VTW_STRING, 0, 1},
    {"memory_pattern_ips", 58, YX_VTW_STRING, 0, 1},
    {"memory_pattern_domains", 59, YX_VTW_STRING, 0, 1},
    {"memory_pattern_urls", 60, YX_VTW_STRING, 0, 1},
    {"smtp_conversations", 64, YX_VTW_MESSAGE, 17, 1},
    {"ids_alerts", 68, YX_VTW_MESSAGE, 54, 1},
    {"tls", 69, YX_VTW_MESSAGE, 18, 1},
    {"mitre_attack_techniques", 70, YX_VTW_MESSAGE, 12, 1},
    {"sigma_analysis_results", 71, YX_VTW_MESSAGE, 43, 1},
    {"signature_matches", 72, YX_VTW_MESSAGE, 15, 1},
    {"mbc", 74, YX_VTW_MESSAGE, 11, 1},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_DnsLookup[] = {
    {"hostname", 1, YX_VTW_STRING, 0, 0},
    {"resolved_ips", 2, YX_VTW_STRING, 0, 1},
    {"txt_records", 3, YX_VTW_STRING, 0, 1},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_DroppedFile[] = {
    {"path", 1, YX_VTW_STRING, 0, 0},
    {"sha256", 2, YX_VTW_STRING, 0, 0},
    {"type", 3, YX_VTW_INT32, 0, 0},
    {"download_url", 5, YX_VTW_STRING, 0, 0},
    {"process_name", 6, YX_VTW_STRING, 0, 0},
    {"process_id", 7, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_ExtractedPayload[] = {
    {"sha256", 1, YX_VTW_STRING, 0, 0},
    {"type", 2, YX_VTW_INT32, 0, 0},
    {"size", 3, YX_VTW_UINT64, 0, 0},
    {"payload_type", 4, YX_VTW_STRING, 0, 0},
    {"process_name", 5, YX_VTW_STRING, 0, 0},
    {"timestamp", 6, YX_VTW_MESSAGE, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_FileCopy[] = {
    {"source", 1, YX_VTW_STRING, 0, 0},
    {"destination", 2, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_HttpConversation[] = {
    {"url", 1, YX_VTW_STRING, 0, 0},
    {"request_method", 2, YX_VTW_INT32, 0, 0},
    {"request_headers", 3, YX_VTW_MESSAGE, 1, 3},
    {"response_headers", 4, YX_VTW_MESSAGE, 1, 3},
    {"response_status_code", 5, YX_VTW_INT32, 0, 0},
    {"response_body_filetype", 6, YX_VTW_INT32, 0, 0},
    {"response_body_first_ten_bytes", 7, YX_VTW_STRING, 0, 4},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_IpTraffic[] = {
    {"destination_ip", 1, YX_VTW_STRING, 0, 0},
    {"destination_port", 2, YX_VTW_INT32, 0, 0},
    {"transport_layer_protocol", 3, YX_VTW_INT32, 0, 0},
    {"destination_ip_asn", 4, YX_VTW_INT64, 0, 0},
    {"destination_ip_as_int", 5, YX_VTW_INT64, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_KeyValue[] = {
    {"key", 1, YX_VTW_STRING, 0, 0},
    {"value", 2, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_MalwareBehaviorCatalog[] = {
    {"id", 1, YX_VTW_STRING, 0, 0},
    {"objective", 2, YX_VTW_STRING, 0, 0},
    {"behavior", 3, YX_VTW_STRING, 0, 0},
    {"method", 4, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_MitreAttackTechnique[] = {
    {"id", 1, YX_VTW_STRING, 0, 0},
    {"severity", 2, YX_VTW_INT32, 0, 0},
    {"signature_description", 3, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_PermissionCheck[] = {
    {"permission", 1, YX_VTW_STRING, 0, 0},
    {"owner", 2, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_ProcessItem[] = {
    {"process_id", 1, YX_VTW_STRING, 0, 0},
    {"parent_process_id", 2, YX_VTW_STRING, 0, 0},
    {"name", 3, YX_VTW_STRING, 0, 0},
    {"parent_name", 10, YX_VTW_STRING, 0, 0},
    {"start_time", 4, YX_VTW_UINT64, 0, 0},
    {"termination_time", 5, YX_VTW_UINT64, 0, 0},
    {"files_opened", 6, YX_VTW_STRING, 0, 1},
    {"files_written", 7, YX_VTW_STRING, 0, 1},
    {"files_deleted", 8, YX_VTW_STRING, 0, 1},
    {"files_copied", 9, YX_VTW_MESSAGE, 7, 1},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_SignatureMatch[] = {
    {"id", 1, YX_VTW_STRING, 0, 0},
    {"format", 2, YX_VTW_INT32, 0, 0},
    {"name", 3, YX_VTW_STRING, 0, 0},
    {"description", 4, YX_VTW_STRING, 0, 0},
    {"authors", 5, YX_VTW_STRING, 0, 1},
    {"events", 6, YX_VTW_STRING, 0, 1},
    {"match_data", 7, YX_VTW_STRING, 0, 1},
    {"rule_src", 8, YX_VTW_STRING, 0, 0},
    {"severity", 9, YX_VTW_INT32, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_Sms[] = {
    {"destination", 1, YX_VTW_STRING, 0, 0},
    {"body", 2, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_SmtpConversation[] = {
    {"hostname", 1, YX_VTW_STRING, 0, 0},
    {"destination_ip", 2, YX_VTW_STRING, 0, 0},
    {"destination_port", 3, YX_VTW_UINT32, 0, 0},
    {"smtp_from", 4, YX_VTW_STRING, 0, 0},
    {"smtp_to", 5, YX_VTW_STRING, 0, 1},
    {"message_from", 6, YX_VTW_STRING, 0, 1},
    {"message_to", 7, YX_VTW_STRING, 0, 1},
    {"message_cc", 8, YX_VTW_STRING, 0, 1},
    {"message_bcc", 9, YX_VTW_STRING, 0, 1},
    {"timestamp", 10, YX_VTW_STRING, 0, 0},
    {"subject", 11, YX_VTW_STRING, 0, 0},
    {"html_body", 12, YX_VTW_STRING, 0, 0},
    {"txt_body", 13, YX_VTW_STRING, 0, 0},
    {"auth_user", 14, YX_VTW_STRING, 0, 0},
    {"auth_pass", 15, YX_VTW_STRING, 0, 0},
    {"headers", 16, YX_VTW_MESSAGE, 10, 1},
    {"attachments", 17, YX_VTW_MESSAGE, 5, 1},
    {"x_mailer", 18, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_fileanalysis_TLS[] = {
    {"subject", 1, YX_VTW_MESSAGE, 1, 3},
    {"issuer", 2, YX_VTW_MESSAGE, 1, 3},
    {"serial_number", 3, YX_VTW_STRING, 0, 0},
    {"thumbprint", 4, YX_VTW_STRING, 0, 0},
    {"version", 5, YX_VTW_STRING, 0, 0},
    {"sni", 6, YX_VTW_STRING, 0, 0},
    {"ja3", 7, YX_VTW_STRING, 0, 0},
    {"ja3s", 8, YX_VTW_STRING, 0, 0},
    {"ja4", 10, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_hunting_gti_score_HuntingGtiScore[] = {
    {"verdict", 1, YX_VTW_MESSAGE, 22, 0},
    {"threat_score", 2, YX_VTW_MESSAGE, 21, 0},
    {"severity", 3, YX_VTW_MESSAGE, 20, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_hunting_gti_score_HuntingGtiSeverity[] = {
    {"value", 1, YX_VTW_INT32, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_hunting_gti_score_HuntingGtiThreatScore[] = {
    {"value", 1, YX_VTW_INT32, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_hunting_gti_score_HuntingGtiVerdict[] = {
    {"value", 1, YX_VTW_INT32, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_ConsoleMessage[] = {
    {"content", 1, YX_VTW_STRING, 0, 0},
    {"source_file", 2, YX_VTW_STRING, 0, 0},
    {"level", 3, YX_VTW_INT32, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_DNSRecord[] = {
    {"type", 2, YX_VTW_STRING, 0, 0},
    {"dns_class", 3, YX_VTW_STRING, 0, 0},
    {"ttl", 4, YX_VTW_INT64, 0, 0},
    {"mname", 5, YX_VTW_STRING, 0, 0},
    {"rname", 6, YX_VTW_STRING, 0, 0},
    {"priority", 7, YX_VTW_INT64, 0, 0},
    {"serial", 8, YX_VTW_INT64, 0, 0},
    {"retry", 9, YX_VTW_INT64, 0, 0},
    {"refresh", 10, YX_VTW_INT64, 0, 0},
    {"expire", 11, YX_VTW_INT64, 0, 0},
    {"minimum", 12, YX_VTW_INT64, 0, 0},
    {"value", 13, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_EnrichedDomain[] = {
    {"raw", 18, YX_VTW_STRING, 0, 0},
    {"root", 27, YX_VTW_STRING, 0, 0},
    {"whois", 3, YX_VTW_MESSAGE, 1, 3},
    {"whois_raw", 26, YX_VTW_STRING, 0, 0},
    {"https_certificate", 4, YX_VTW_MESSAGE, 35, 0},
    {"jarm", 5, YX_VTW_STRING, 0, 0},
    {"dns_records", 6, YX_VTW_MESSAGE, 24, 1},
    {"favicon", 7, YX_VTW_MESSAGE, 30, 0},
    {"analysis_stats", 12, YX_VTW_MESSAGE, 2, 0},
    {"signatures", 13, YX_VTW_MESSAGE, 1, 3},
    {"new_domain", 16, YX_VTW_BOOL, 0, 0},
    {"tags", 17, YX_VTW_STRING, 0, 1},
    {"downloaded_file", 19, YX_VTW_MESSAGE, 31, 0},
    {"communicating_file", 20, YX_VTW_MESSAGE, 31, 0},
    {"first_whois", 21, YX_VTW_BOOL, 0, 0},
    {"new_whois", 22, YX_VTW_BOOL, 0, 0},
    {"first_resolution", 23, YX_VTW_BOOL, 0, 0},
    {"new_resolution", 24, YX_VTW_BOOL, 0, 0},
    {"categories", 28, YX_VTW_MESSAGE, 1, 3},
    {"popularity_ranks", 30, YX_VTW_MESSAGE, 33, 1},
    {"number_of_popularity_ranks", 31, YX_VTW_INT64, 0, 0},
    {"root_popularity_ranks", 32, YX_VTW_MESSAGE, 33, 1},
    {"number_of_root_popularity_ranks", 33, YX_VTW_INT64, 0, 0},
    {"gti_assessment", 37, YX_VTW_MESSAGE, 19, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_EnrichedIP[] = {
    {"whois", 3, YX_VTW_MESSAGE, 1, 3},
    {"whois_raw", 22, YX_VTW_STRING, 0, 0},
    {"https_certificate", 4, YX_VTW_MESSAGE, 35, 0},
    {"jarm", 5, YX_VTW_STRING, 0, 0},
    {"ip_as_owner", 6, YX_VTW_STRING, 0, 0},
    {"ip_asn", 7, YX_VTW_INT64, 0, 0},
    {"ip_country", 8, YX_VTW_STRING, 0, 0},
    {"analysis_stats", 13, YX_VTW_MESSAGE, 2, 0},
    {"signatures", 14, YX_VTW_MESSAGE, 1, 3},
    {"tags", 17, YX_VTW_STRING, 0, 1},
    {"raw", 18, YX_VTW_STRING, 0, 0},
    {"downloaded_file", 19, YX_VTW_MESSAGE, 31, 0},
    {"communicating_file", 20, YX_VTW_MESSAGE, 31, 0},
    {"ip_as_int", 23, YX_VTW_INT64, 0, 0},
    {"first_whois", 24, YX_VTW_BOOL, 0, 0},
    {"new_whois", 25, YX_VTW_BOOL, 0, 0},
    {"reverse_lookup", 26, YX_VTW_STRING, 0, 0},
    {"gti_assessment", 30, YX_VTW_MESSAGE, 19, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_EnrichedNetloc[] = {
    {"url", 1, YX_VTW_MESSAGE, 28, 0},
    {"ip", 2, YX_VTW_MESSAGE, 26, 0},
    {"domain", 3, YX_VTW_MESSAGE, 25, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_EnrichedURL[] = {
    {"port", 3, YX_VTW_INT64, 0, 0},
    {"trackers", 4, YX_VTW_MESSAGE, 37, 1},
    {"response_headers", 5, YX_VTW_MESSAGE, 1, 3},
    {"number_of_response_headers", 33, YX_VTW_INT64, 0, 0},
    {"response_code", 6, YX_VTW_INT64, 0, 0},
    {"cookies", 7, YX_VTW_MESSAGE, 1, 3},
    {"favicon", 8, YX_VTW_MESSAGE, 30, 0},
    {"outgoing_links", 9, YX_VTW_STRING, 0, 1},
    {"redirects", 10, YX_VTW_STRING, 0, 1},
    {"html_title", 11, YX_VTW_STRING, 0, 0},
    {"html_meta_tags", 12, YX_VTW_MESSAGE, 32, 1},
    {"new_url", 17, YX_VTW_BOOL, 0, 0},
    {"analysis_stats", 18, YX_VTW_MESSAGE, 2, 0},
    {"first_submission_date", 19, YX_VTW_INT64, 0, 0},
    {"signatures", 20, YX_VTW_MESSAGE, 1, 3},
    {"submitter", 21, YX_VTW_MESSAGE, 46, 0},
    {"tags", 24, YX_VTW_STRING, 0, 1},
    {"query", 34, YX_VTW_STRING, 0, 0},
    {"params", 25, YX_VTW_MESSAGE, 1, 3},
    {"path", 26, YX_VTW_STRING, 0, 0},
    {"hostname", 27, YX_VTW_STRING, 0, 0},
    {"raw", 28, YX_VTW_STRING, 0, 0},
    {"downloaded_file", 29, YX_VTW_MESSAGE, 31, 0},
    {"communicating_file", 30, YX_VTW_MESSAGE, 31, 0},
    {"embedded_resources", 31, YX_VTW_MESSAGE, 34, 1},
    {"categories", 35, YX_VTW_MESSAGE, 1, 3},
    {"gti_assessment", 39, YX_VTW_MESSAGE, 19, 0},
    {"resources", 40, YX_VTW_MESSAGE, 38, 1},
    {"cookies_extended", 45, YX_VTW_MESSAGE, 29, 1},
    {"javascript_variables", 46, YX_VTW_MESSAGE, 1, 3},
    {"console_messages", 47, YX_VTW_MESSAGE, 23, 1},
    {"web_technologies", 48, YX_VTW_MESSAGE, 40, 1},
    {"filename", 49, YX_VTW_STRING, 0, 0},
    {"tls", 50, YX_VTW_MESSAGE, 35, 1},
    {"dom_sha256", 51, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_ExtendedCookie[] = {
    {"name", 1, YX_VTW_STRING, 0, 0},
    {"value", 2, YX_VTW_STRING, 0, 0},
    {"domain", 3, YX_VTW_STRING, 0, 0},
    {"expires", 4, YX_VTW_INT64, 0, 0},
    {"secure", 5, YX_VTW_BOOL, 0, 0},
    {"http_only", 6, YX_VTW_BOOL, 0, 0},
    {"session", 7, YX_VTW_BOOL, 0, 0},
    {"size", 8, YX_VTW_INT32, 0, 0},
    {"priority", 9, YX_VTW_INT32, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_Favicon[] = {
    {"raw_md5", 1, YX_VTW_STRING, 0, 0},
    {"dhash", 2, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_FileMetadata[] = {
    {"sha256", 1, YX_VTW_STRING, 0, 0},
    {"new_for_vt", 3, YX_VTW_BOOL, 0, 0},
    {"analysis_stats", 5, YX_VTW_MESSAGE, 2, 0},
    {"file_type", 6, YX_VTW_INT32, 0, 0},
    {"new_for_url", 7, YX_VTW_BOOL, 0, 0},
    {"new_for_ip", 8, YX_VTW_BOOL, 0, 0},
    {"new_for_domain", 9, YX_VTW_BOOL, 0, 0},
    {"signatures", 10, YX_VTW_MESSAGE, 1, 3},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_KeyValue[] = {
    {"key", 1, YX_VTW_STRING, 0, 0},
    {"values", 2, YX_VTW_STRING, 0, 1},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_PopularityRank[] = {
    {"position", 1, YX_VTW_INT64, 0, 0},
    {"ingestion_time", 2, YX_VTW_INT64, 0, 0},
    {"rank", 3, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_ResourceFileMetadata[] = {
    {"sha256", 1, YX_VTW_STRING, 0, 0},
    {"analysis_stats", 2, YX_VTW_MESSAGE, 2, 0},
    {"file_type", 3, YX_VTW_INT32, 0, 0},
    {"new_for_url", 4, YX_VTW_BOOL, 0, 0},
    {"signatures", 5, YX_VTW_MESSAGE, 1, 3},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_SSLCertificate[] = {
    {"thumbprint", 1, YX_VTW_STRING, 0, 0},
    {"subject", 2, YX_VTW_MESSAGE, 36, 0},
    {"validity", 3, YX_VTW_MESSAGE, 39, 0},
    {"subject_alternative_name", 4, YX_VTW_STRING, 0, 1},
    {"signature", 5, YX_VTW_STRING, 0, 0},
    {"serial_number", 6, YX_VTW_STRING, 0, 0},
    {"issuer", 7, YX_VTW_MESSAGE, 36, 0},
    {"host", 8, YX_VTW_STRING, 0, 0},
    {"version", 9, YX_VTW_STRING, 0, 0},
    {"algorithm", 10, YX_VTW_STRING, 0, 0},
    {"signature_algorithm", 11, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_Subject[] = {
    {"common_name", 1, YX_VTW_STRING, 0, 0},
    {"country", 2, YX_VTW_STRING, 0, 0},
    {"organization", 3, YX_VTW_STRING, 0, 0},
    {"organizational_unit", 4, YX_VTW_STRING, 0, 0},
    {"locality", 5, YX_VTW_STRING, 0, 0},
    {"state", 6, YX_VTW_STRING, 0, 0},
    {"alternative_names", 7, YX_VTW_STRING, 0, 1},
    {"street_address", 8, YX_VTW_STRING, 0, 0},
    {"postal_code", 9, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_Tracker[] = {
    {"name", 1, YX_VTW_STRING, 0, 0},
    {"id", 2, YX_VTW_STRING, 0, 0},
    {"url", 3, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_URLResource[] = {
    {"url", 1, YX_VTW_STRING, 0, 0},
    {"method", 2, YX_VTW_INT32, 0, 0},
    {"sha256", 3, YX_VTW_STRING, 0, 0},
    {"response_code", 4, YX_VTW_INT32, 0, 0},
    {"serving_ip_address", 5, YX_VTW_STRING, 0, 0},
    {"content_length", 6, YX_VTW_INT32, 0, 0},
    {"reverse_dns", 7, YX_VTW_STRING, 0, 0},
    {"type", 8, YX_VTW_INT32, 0, 0},
    {"browser_type", 9, YX_VTW_INT32, 0, 0},
    {"response_headers", 10, YX_VTW_MESSAGE, 1, 3},
    {"net_error", 11, YX_VTW_INT32, 0, 0},
    {"redirects", 12, YX_VTW_STRING, 0, 1},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_Validity[] = {
    {"not_after", 1, YX_VTW_INT64, 0, 0},
    {"not_before", 2, YX_VTW_INT64, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_net_WebTechnology[] = {
    {"name", 1, YX_VTW_STRING, 0, 0},
    {"version", 2, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_sigma_Detection[] = {
    {"condition", 1, YX_VTW_STRING, 0, 0},
    {"details", 2, YX_VTW_MESSAGE, 1, 3},
};
static const yx_vt_wire_field yx_vt_wire_vt_sigma_LogSource[] = {
    {"category", 1, YX_VTW_STRING, 0, 0},
    {"product", 2, YX_VTW_STRING, 0, 0},
    {"service", 3, YX_VTW_STRING, 0, 0},
    {"definition", 4, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_sigma_SigmaMatch[] = {
    {"match_context", 1, YX_VTW_MESSAGE, 44, 1},
    {"rule_level", 2, YX_VTW_INT32, 0, 0},
    {"rule_id", 3, YX_VTW_STRING, 0, 0},
    {"rule_source", 4, YX_VTW_STRING, 0, 0},
    {"rule_title", 5, YX_VTW_STRING, 0, 0},
    {"rule_description", 6, YX_VTW_STRING, 0, 0},
    {"rule_author", 7, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_sigma_SigmaMatchContext[] = {
    {"values", 1, YX_VTW_MESSAGE, 1, 3},
};
static const yx_vt_wire_field yx_vt_wire_vt_sigma_SigmaRule[] = {
    {"rule", 1, YX_VTW_STRING, 0, 0},
    {"title", 2, YX_VTW_STRING, 0, 0},
    {"log_source", 3, YX_VTW_MESSAGE, 42, 0},
    {"status", 4, YX_VTW_STRING, 0, 0},
    {"description", 5, YX_VTW_STRING, 0, 0},
    {"references", 6, YX_VTW_STRING, 0, 1},
    {"fields", 7, YX_VTW_STRING, 0, 1},
    {"false_positives", 8, YX_VTW_STRING, 0, 1},
    {"level", 9, YX_VTW_INT32, 0, 0},
    {"source", 10, YX_VTW_STRING, 0, 0},
    {"tags", 11, YX_VTW_STRING, 0, 1},
    {"detection", 12, YX_VTW_MESSAGE, 41, 0},
    {"author", 13, YX_VTW_STRING, 0, 0},
    {"source_url", 14, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_submitter_Submitter[] = {
    {"city", 6, YX_VTW_STRING, 0, 0},
    {"country", 8, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_titan_FileMetadata[] = {
    {"sha256", 1, YX_VTW_STRING, 0, 0},
    {"sha1", 2, YX_VTW_STRING, 0, 0},
    {"md5", 3, YX_VTW_STRING, 0, 0},
    {"ssdeep", 4, YX_VTW_STRING, 0, 0},
    {"imphash", 5, YX_VTW_STRING, 0, 0},
    {"vhash", 6, YX_VTW_STRING, 0, 0},
    {"telfhash", 27, YX_VTW_STRING, 0, 0},
    {"file_name", 7, YX_VTW_STRING, 0, 0},
    {"file_type", 8, YX_VTW_INT32, 0, 0},
    {"file_size", 9, YX_VTW_INT64, 0, 0},
    {"times_submitted", 10, YX_VTW_INT32, 0, 0},
    {"new_file", 11, YX_VTW_BOOL, 0, 0},
    {"tags", 12, YX_VTW_STRING, 0, 1},
    {"signatures", 13, YX_VTW_MESSAGE, 1, 3},
    {"submitter", 15, YX_VTW_MESSAGE, 46, 0},
    {"subfile", 16, YX_VTW_BOOL, 0, 0},
    {"unique_sources", 17, YX_VTW_INT32, 0, 0},
    {"analysis_stats", 18, YX_VTW_MESSAGE, 2, 0},
    {"magic", 19, YX_VTW_STRING, 0, 0},
    {"file_type_tags", 20, YX_VTW_STRING, 0, 1},
    {"first_submission_date", 22, YX_VTW_INT64, 0, 0},
    {"exiftool", 25, YX_VTW_MESSAGE, 1, 3},
    {"main_icon", 26, YX_VTW_MESSAGE, 52, 0},
    {"goresym", 28, YX_VTW_MESSAGE, 48, 0},
    {"malware_families", 30, YX_VTW_STRING, 0, 1},
    {"tlsh", 31, YX_VTW_STRING, 0, 0},
    {"itw", 32, YX_VTW_MESSAGE, 27, 0},
    {"gti_assessment", 36, YX_VTW_MESSAGE, 19, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_titan_GoReSym[] = {
    {"version", 1, YX_VTW_STRING, 0, 0},
    {"arch", 2, YX_VTW_STRING, 0, 0},
    {"os", 3, YX_VTW_STRING, 0, 0},
    {"build_id", 4, YX_VTW_STRING, 0, 0},
    {"build_info", 5, YX_VTW_MESSAGE, 49, 0},
    {"summary", 6, YX_VTW_MESSAGE, 50, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_titan_GoReSym_BuildInfo[] = {
    {"path", 1, YX_VTW_STRING, 0, 0},
    {"dependencies", 2, YX_VTW_MESSAGE, 1, 3},
    {"settings", 3, YX_VTW_MESSAGE, 1, 3},
};
static const yx_vt_wire_field yx_vt_wire_vt_titan_GoReSym_Summary[] = {
    {"num_user_functions", 1, YX_VTW_INT64, 0, 0},
    {"num_std_functions", 2, YX_VTW_INT64, 0, 0},
    {"num_interfaces", 3, YX_VTW_INT64, 0, 0},
    {"num_types", 4, YX_VTW_INT64, 0, 0},
    {"num_dependencies", 5, YX_VTW_INT64, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_titan_LiveHuntData[] = {
    {"metadata", 1, YX_VTW_MESSAGE, 47, 0},
    {"behaviour", 2, YX_VTW_MESSAGE, 3, 0},
    {"net", 3, YX_VTW_MESSAGE, 27, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_titan_MainIcon[] = {
    {"dhash", 1, YX_VTW_STRING, 0, 0},
    {"raw_md5", 2, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_tools_net_analysis_CrowdSourcedIdsAlertContext[] = {
    {"protocol", 1, YX_VTW_INT32, 0, 0},
    {"src_ip", 2, YX_VTW_STRING, 0, 0},
    {"src_port", 3, YX_VTW_UINT32, 0, 0},
    {"dest_ip", 4, YX_VTW_STRING, 0, 0},
    {"dest_port", 5, YX_VTW_UINT32, 0, 0},
    {"hostname", 6, YX_VTW_STRING, 0, 0},
    {"url", 7, YX_VTW_STRING, 0, 0},
    {"ja3", 8, YX_VTW_STRING, 0, 1},
    {"ja3s", 9, YX_VTW_STRING, 0, 1},
};
static const yx_vt_wire_field yx_vt_wire_vt_tools_net_analysis_CrowdSourcedIdsResults[] = {
    {"rule_msg", 1, YX_VTW_STRING, 0, 0},
    {"rule_category", 2, YX_VTW_STRING, 0, 0},
    {"rule_id", 3, YX_VTW_STRING, 0, 0},
    {"alert_severity", 4, YX_VTW_INT32, 0, 0},
    {"rule_source", 5, YX_VTW_STRING, 0, 0},
    {"alert_context", 6, YX_VTW_MESSAGE, 53, 0},
    {"rule_url", 7, YX_VTW_STRING, 0, 0},
    {"rule_references", 8, YX_VTW_STRING, 0, 1},
    {"tags", 9, YX_VTW_STRING, 0, 1},
    {"rule_raw", 10, YX_VTW_STRING, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_urlheadless_ConsoleMessage[] = {
    {"content", 1, YX_VTW_STRING, 0, 0},
    {"source_file", 2, YX_VTW_STRING, 0, 0},
    {"level", 3, YX_VTW_INT32, 0, 0},
};
static const yx_vt_wire_field yx_vt_wire_vt_urlheadless_Cookie[] = {
    {"name", 1, YX_VTW_STRING, 0, 0},
    {"value", 2, YX_VTW_STRING, 0, 0},
    {"domain", 3, YX_VTW_STRING, 0, 0},
    {"expires", 4, YX_VTW_INT32, 0, 0},
    {"size", 5, YX_VTW_INT32, 0, 0},
    {"http_only", 6, YX_VTW_BOOL, 0, 0},
    {"secure", 7, YX_VTW_BOOL, 0, 0},
    {"session", 8, YX_VTW_BOOL, 0, 0},
    {"priority", 9, YX_VTW_INT32, 0, 0},
};
static const yx_vt_wire_message yx_vt_wire_messages[] = {
    {"google.protobuf.Timestamp", yx_vt_wire_google_protobuf_Timestamp, 2},
    {"vt.MapEntry", yx_vt_wire_vt_MapEntry, 2},
    {"vt.analysis.AnalysisStats", yx_vt_wire_vt_analysis_AnalysisStats, 6},
    {"vt.fileanalysis.BehaviourSummary", yx_vt_wire_vt_fileanalysis_BehaviourSummary, 68},
    {"vt.fileanalysis.DnsLookup", yx_vt_wire_vt_fileanalysis_DnsLookup, 3},
    {"vt.fileanalysis.DroppedFile", yx_vt_wire_vt_fileanalysis_DroppedFile, 6},
    {"vt.fileanalysis.ExtractedPayload", yx_vt_wire_vt_fileanalysis_ExtractedPayload, 6},
    {"vt.fileanalysis.FileCopy", yx_vt_wire_vt_fileanalysis_FileCopy, 2},
    {"vt.fileanalysis.HttpConversation", yx_vt_wire_vt_fileanalysis_HttpConversation, 7},
    {"vt.fileanalysis.IpTraffic", yx_vt_wire_vt_fileanalysis_IpTraffic, 5},
    {"vt.fileanalysis.KeyValue", yx_vt_wire_vt_fileanalysis_KeyValue, 2},
    {"vt.fileanalysis.MalwareBehaviorCatalog", yx_vt_wire_vt_fileanalysis_MalwareBehaviorCatalog, 4},
    {"vt.fileanalysis.MitreAttackTechnique", yx_vt_wire_vt_fileanalysis_MitreAttackTechnique, 3},
    {"vt.fileanalysis.PermissionCheck", yx_vt_wire_vt_fileanalysis_PermissionCheck, 2},
    {"vt.fileanalysis.ProcessItem", yx_vt_wire_vt_fileanalysis_ProcessItem, 10},
    {"vt.fileanalysis.SignatureMatch", yx_vt_wire_vt_fileanalysis_SignatureMatch, 9},
    {"vt.fileanalysis.Sms", yx_vt_wire_vt_fileanalysis_Sms, 2},
    {"vt.fileanalysis.SmtpConversation", yx_vt_wire_vt_fileanalysis_SmtpConversation, 18},
    {"vt.fileanalysis.TLS", yx_vt_wire_vt_fileanalysis_TLS, 9},
    {"vt.hunting_gti_score.HuntingGtiScore", yx_vt_wire_vt_hunting_gti_score_HuntingGtiScore, 3},
    {"vt.hunting_gti_score.HuntingGtiSeverity", yx_vt_wire_vt_hunting_gti_score_HuntingGtiSeverity, 1},
    {"vt.hunting_gti_score.HuntingGtiThreatScore", yx_vt_wire_vt_hunting_gti_score_HuntingGtiThreatScore, 1},
    {"vt.hunting_gti_score.HuntingGtiVerdict", yx_vt_wire_vt_hunting_gti_score_HuntingGtiVerdict, 1},
    {"vt.net.ConsoleMessage", yx_vt_wire_vt_net_ConsoleMessage, 3},
    {"vt.net.DNSRecord", yx_vt_wire_vt_net_DNSRecord, 12},
    {"vt.net.EnrichedDomain", yx_vt_wire_vt_net_EnrichedDomain, 24},
    {"vt.net.EnrichedIP", yx_vt_wire_vt_net_EnrichedIP, 18},
    {"vt.net.EnrichedNetloc", yx_vt_wire_vt_net_EnrichedNetloc, 3},
    {"vt.net.EnrichedURL", yx_vt_wire_vt_net_EnrichedURL, 35},
    {"vt.net.ExtendedCookie", yx_vt_wire_vt_net_ExtendedCookie, 9},
    {"vt.net.Favicon", yx_vt_wire_vt_net_Favicon, 2},
    {"vt.net.FileMetadata", yx_vt_wire_vt_net_FileMetadata, 8},
    {"vt.net.KeyValue", yx_vt_wire_vt_net_KeyValue, 2},
    {"vt.net.PopularityRank", yx_vt_wire_vt_net_PopularityRank, 3},
    {"vt.net.ResourceFileMetadata", yx_vt_wire_vt_net_ResourceFileMetadata, 5},
    {"vt.net.SSLCertificate", yx_vt_wire_vt_net_SSLCertificate, 11},
    {"vt.net.Subject", yx_vt_wire_vt_net_Subject, 9},
    {"vt.net.Tracker", yx_vt_wire_vt_net_Tracker, 3},
    {"vt.net.URLResource", yx_vt_wire_vt_net_URLResource, 12},
    {"vt.net.Validity", yx_vt_wire_vt_net_Validity, 2},
    {"vt.net.WebTechnology", yx_vt_wire_vt_net_WebTechnology, 2},
    {"vt.sigma.Detection", yx_vt_wire_vt_sigma_Detection, 2},
    {"vt.sigma.LogSource", yx_vt_wire_vt_sigma_LogSource, 4},
    {"vt.sigma.SigmaMatch", yx_vt_wire_vt_sigma_SigmaMatch, 7},
    {"vt.sigma.SigmaMatchContext", yx_vt_wire_vt_sigma_SigmaMatchContext, 1},
    {"vt.sigma.SigmaRule", yx_vt_wire_vt_sigma_SigmaRule, 14},
    {"vt.submitter.Submitter", yx_vt_wire_vt_submitter_Submitter, 2},
    {"vt.titan.FileMetadata", yx_vt_wire_vt_titan_FileMetadata, 28},
    {"vt.titan.GoReSym", yx_vt_wire_vt_titan_GoReSym, 6},
    {"vt.titan.GoReSym.BuildInfo", yx_vt_wire_vt_titan_GoReSym_BuildInfo, 3},
    {"vt.titan.GoReSym.Summary", yx_vt_wire_vt_titan_GoReSym_Summary, 5},
    {"vt.titan.LiveHuntData", yx_vt_wire_vt_titan_LiveHuntData, 3},
    {"vt.titan.MainIcon", yx_vt_wire_vt_titan_MainIcon, 2},
    {"vt.tools.net_analysis.CrowdSourcedIdsAlertContext", yx_vt_wire_vt_tools_net_analysis_CrowdSourcedIdsAlertContext, 9},
    {"vt.tools.net_analysis.CrowdSourcedIdsResults", yx_vt_wire_vt_tools_net_analysis_CrowdSourcedIdsResults, 10},
    {"vt.urlheadless.ConsoleMessage", yx_vt_wire_vt_urlheadless_ConsoleMessage, 3},
    {"vt.urlheadless.Cookie", yx_vt_wire_vt_urlheadless_Cookie, 9},
};
#define YX_VT_ROOT_MESSAGE 51
