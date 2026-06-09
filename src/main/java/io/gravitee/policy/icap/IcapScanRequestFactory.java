package io.gravitee.policy.icap;

import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.context.HttpExecutionContext;
import io.gravitee.policy.icap.configuration.IcapContentScanPolicyConfiguration;
import io.gravitee.resource.icap.model.IcapPhase;
import io.gravitee.resource.icap.model.IcapScanMode;
import io.gravitee.resource.icap.model.IcapScanRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;

@Slf4j
final class IcapScanRequestFactory {

  private IcapScanRequestFactory() {}

  static IcapScanRequest build(
    HttpExecutionContext ctx,
    IcapContentScanPolicyConfiguration configuration,
    IcapPhase phase,
    byte[] body
  ) {
    IcapScanMode scanMode = configuration.getScanMode() != null
      ? configuration.getScanMode()
      : IcapScanMode.AUTO;
    int previewBytes = configuration.getPreviewBytes();

    if (phase == IcapPhase.REQUEST) {
      Map<String, String> headers = filterHeaders(
        ctx.request().headers(),
        configuration.getForwardedRequestHeaders()
      );
      log.debug(
        "ICAP scan request built for request {} phase REQUEST: scanMode={}, previewBytes={}, bodyBytes={}, forwardedHeaders={}",
        ctx.request().id(),
        scanMode,
        previewBytes,
        body != null ? body.length : 0,
        headers.size()
      );
      return IcapScanRequest.builder()
        .phase(IcapPhase.REQUEST)
        .scanMode(scanMode)
        .previewBytes(previewBytes)
        .body(body)
        .method(ctx.request().method().name())
        .path(ctx.request().path())
        .host(ctx.request().host())
        .headers(headers)
        .build();
    }

    Map<String, String> headers = filterHeaders(
      ctx.response().headers(),
      configuration.getForwardedResponseHeaders()
    );
    log.debug(
      "ICAP scan request built for request {} phase RESPONSE: scanMode={}, previewBytes={}, bodyBytes={}, httpStatus={}, forwardedHeaders={}",
      ctx.request().id(),
      scanMode,
      previewBytes,
      body != null ? body.length : 0,
      ctx.response().status(),
      headers.size()
    );
    return IcapScanRequest.builder()
      .phase(IcapPhase.RESPONSE)
      .scanMode(scanMode)
      .previewBytes(previewBytes)
      .body(body)
      .httpStatus(ctx.response().status())
      .headers(headers)
      .build();
  }

  private static Map<String, String> filterHeaders(
    HttpHeaders headers,
    List<String> allowlist
  ) {
    Map<String, String> result = new HashMap<>();
    if (headers == null || allowlist == null) {
      return result;
    }
    for (String allowed : allowlist) {
      String value = headers.get(allowed);
      if (value != null) {
        result.put(allowed, value);
      }
    }
    return result;
  }
}
