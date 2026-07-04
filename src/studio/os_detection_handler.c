#include <pb_decode.h>
#include <pb_encode.h>
#include <zephyr/sys/util.h>
#include <zmk/studio/custom.h>
#include <cormoran/os-detection/os_detection.pb.h>

#if IS_ENABLED(CONFIG_ZMK_CUSTOM_SETTINGS)
#include <cormoran/zmk/custom_settings.h>
#endif

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_LOG_LEVEL);

static struct zmk_rpc_custom_subsystem_meta os_detection_meta = {
    ZMK_RPC_CUSTOM_SUBSYSTEM_UI_URLS("https://cormoran.github.io/zmk-feature-os-detection/"),
    // Unsecured is suggested by default to avoid unlocking in un-reliable
    // environments.
    .security = ZMK_STUDIO_RPC_HANDLER_UNSECURED,
};

ZMK_RPC_CUSTOM_SUBSYSTEM(cormoran__os_detection, &os_detection_meta,
                         os_detection_rpc_handle_request);

ZMK_RPC_CUSTOM_SUBSYSTEM_RESPONSE_BUFFER(cormoran__os_detection, cormoran_os_detection_Response);

#if IS_ENABLED(CONFIG_ZMK_CUSTOM_SETTINGS)
ZMK_CUSTOM_SETTING_DEFINE(os_detection_sample_bool, "cormoran__os_detection", "sample_bool",
                          ZMK_CUSTOM_SETTING_VALUE_TYPE_BOOL, ZMK_CUSTOM_SETTING_VALUE_BOOL(true),
                          ZMK_CUSTOM_SETTING_CONFIDENTIALITY_RPC_PUBLIC,
                          ZMK_CUSTOM_SETTING_PERMISSION_UNSECURE,
                          ZMK_CUSTOM_SETTING_PERMISSION_UNSECURE, ZMK_CUSTOM_SETTING_NO_CONSTRAINT);
#endif

static int handle_sample_request(const cormoran_os_detection_SampleRequest *req,
                                 cormoran_os_detection_Response *resp);

static bool os_detection_rpc_handle_request(const zmk_custom_CallRequest *raw_request,
                                            pb_callback_t *encode_response) {
    cormoran_os_detection_Response *resp =
        ZMK_RPC_CUSTOM_SUBSYSTEM_RESPONSE_BUFFER_ALLOCATE(cormoran__os_detection, encode_response);

    cormoran_os_detection_Request req = cormoran_os_detection_Request_init_zero;

    pb_istream_t req_stream =
        pb_istream_from_buffer(raw_request->payload.bytes, raw_request->payload.size);
    if (!pb_decode(&req_stream, cormoran_os_detection_Request_fields, &req)) {
        LOG_WRN("Failed to decode os_detection request: %s", PB_GET_ERROR(&req_stream));
        cormoran_os_detection_ErrorResponse err = cormoran_os_detection_ErrorResponse_init_zero;
        snprintf(err.message, sizeof(err.message), "Failed to decode request");
        resp->which_response_type = cormoran_os_detection_Response_error_tag;
        resp->response_type.error = err;
        return true;
    }

    int rc = 0;
    switch (req.which_request_type) {
    case cormoran_os_detection_Request_sample_tag:
        rc = handle_sample_request(&req.request_type.sample, resp);
        break;
    default:
        LOG_WRN("Unsupported os_detection request type: %d", req.which_request_type);
        rc = -1;
    }

    if (rc != 0) {
        cormoran_os_detection_ErrorResponse err = cormoran_os_detection_ErrorResponse_init_zero;
        snprintf(err.message, sizeof(err.message), "Failed to process request");
        resp->which_response_type = cormoran_os_detection_Response_error_tag;
        resp->response_type.error = err;
    }
    return true;
}

static int handle_sample_request(const cormoran_os_detection_SampleRequest *req,
                                 cormoran_os_detection_Response *resp) {
    LOG_DBG("Received sample request with value: %d", req->value);

    cormoran_os_detection_SampleResponse result = cormoran_os_detection_SampleResponse_init_zero;

    snprintf(result.value, sizeof(result.value), "Hello from firmware! Received: %d", req->value);

    resp->which_response_type = cormoran_os_detection_Response_sample_tag;
    resp->response_type.sample = result;
    return 0;
}
