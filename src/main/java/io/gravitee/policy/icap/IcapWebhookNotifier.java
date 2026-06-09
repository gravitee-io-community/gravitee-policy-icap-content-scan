package io.gravitee.policy.icap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.gateway.reactive.api.context.HttpExecutionContext;
import io.gravitee.policy.icap.configuration.ExecutionMode;
import io.gravitee.policy.icap.configuration.HeaderConfiguration;
import io.gravitee.policy.icap.configuration.IcapContentScanPolicyConfiguration;
import io.gravitee.policy.icap.configuration.WebhookConfiguration;
import io.gravitee.policy.icap.configuration.WebhookTrigger;
import io.gravitee.resource.icap.model.IcapPhase;
import io.gravitee.resource.icap.model.IcapScanResult;
import io.gravitee.resource.icap.model.IcapVerdict;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class IcapWebhookNotifier {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private final IcapContentScanPolicyConfiguration configuration;
  private final HttpClient httpClient = HttpClient.newBuilder()
    .connectTimeout(java.time.Duration.ofSeconds(5))
    .build();

  public void maybeNotify(
    HttpExecutionContext ctx,
    IcapPhase phase,
    byte[] body,
    IcapScanResult result
  ) {
    String requestId = safeRequestId(ctx);
    log.debug(
      "ICAP webhook evaluation started: requestId={}, phase={}, verdict={}, webhookEnabled={}, webhookOn={}",
      requestId,
      phase,
      result != null && result.getVerdict() != null
        ? result.getVerdict()
        : null,
      configuration.isWebhookEnabled(),
      configuration.getWebhookOn()
    );

    if (result == null || result.getVerdict() == null) {
      log.debug(
        "ICAP webhook skipped for request {}: scan result or verdict is null",
        requestId
      );
      return;
    }
    if (!configuration.isWebhookEnabled()) {
      log.debug(
        "ICAP webhook skipped for request {}: webhookEnabled is false",
        requestId
      );
      return;
    }
    if (!shouldNotifyForVerdict(result.getVerdict())) {
      log.debug(
        "ICAP webhook skipped for request {}: verdict {} is not in webhookOn {}",
        requestId,
        result.getVerdict(),
        configuration.getWebhookOn()
      );
      return;
    }

    log.debug(
      "ICAP webhook will be sent for request {}: phase={}, verdict={}",
      requestId,
      phase,
      result.getVerdict()
    );
    notifyScanResult(ctx, phase, body, result);
  }

  boolean shouldNotifyForVerdict(IcapVerdict verdict) {
    List<WebhookTrigger> triggers = configuration.getWebhookOn();
    if (triggers == null || triggers.isEmpty()) {
      return false;
    }
    WebhookTrigger trigger = mapVerdictToTrigger(verdict);
    return trigger != null && triggers.contains(trigger);
  }

  static WebhookTrigger mapVerdictToTrigger(IcapVerdict verdict) {
    return switch (verdict) {
      case CLEAN -> WebhookTrigger.CLEAN;
      case INFECTED -> WebhookTrigger.INFECTED;
      case MODIFIED -> WebhookTrigger.MODIFIED;
      case ERROR -> WebhookTrigger.ERROR;
    };
  }

  void notifyScanResult(
    HttpExecutionContext ctx,
    IcapPhase phase,
    byte[] body,
    IcapScanResult result
  ) {
    String requestId = safeRequestId(ctx);
    WebhookConfiguration webhook = configuration.getWebhook();
    if (
      webhook == null || webhook.getUrl() == null || webhook.getUrl().isBlank()
    ) {
      log.warn(
        "ICAP webhook enabled for request {} but webhook.url is not configured",
        requestId
      );
      return;
    }

    log.debug(
      "ICAP webhook preparing delivery for request {}: configuredUrl={}, method={}, timeoutMs={}, retryCount={}",
      requestId,
      webhook.getUrl(),
      webhook.getMethod(),
      webhook.getTimeoutMs(),
      webhook.getRetryCount()
    );

    try {
      String url = ctx
        .getTemplateEngine()
        .evalNow(webhook.getUrl(), String.class);
      log.debug("ICAP webhook resolved URL for request {}: {}", requestId, url);

      String payload = buildPayload(ctx, phase, body, result, webhook);
      log.debug(
        "ICAP webhook built payload for request {}: {} bytes",
        requestId,
        payload.length()
      );

      int attempts = Math.max(0, webhook.getRetryCount()) + 1;
      for (int attempt = 1; attempt <= attempts; attempt++) {
        try {
          String method = webhook.getMethod() != null
            ? webhook.getMethod()
            : "POST";
          log.debug(
            "ICAP webhook sending attempt {}/{} for request {}: {} {}",
            attempt,
            attempts,
            requestId,
            method,
            url
          );

          HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(java.time.Duration.ofMillis(webhook.getTimeoutMs()))
            .method(method, HttpRequest.BodyPublishers.ofString(payload));
          applyHeaders(ctx, webhook, builder);
          HttpResponse<String> response = httpClient.send(
            builder.build(),
            HttpResponse.BodyHandlers.ofString()
          );
          if (response.statusCode() < 500) {
            log.debug(
              "ICAP webhook delivered for request {}: status={}, attempt={}",
              requestId,
              response.statusCode(),
              attempt
            );
            return;
          }
          log.warn(
            "ICAP webhook returned status {} on attempt {} for request {}",
            response.statusCode(),
            attempt,
            requestId
          );
        } catch (Exception e) {
          log.warn(
            "ICAP webhook attempt {} failed for request {}: {}",
            attempt,
            requestId,
            e.getMessage()
          );
          log.debug(
            "ICAP webhook attempt {} failure details for request {}",
            attempt,
            requestId,
            e
          );
        }
        if (attempt < attempts) {
          TimeUnit.MILLISECONDS.sleep(500L * attempt);
        }
      }
      log.warn(
        "ICAP webhook delivery exhausted retries for request {}",
        requestId
      );
    } catch (Exception e) {
      log.warn(
        "ICAP webhook delivery failed for request {}: {}",
        requestId,
        e.getMessage()
      );
      log.debug(
        "ICAP webhook delivery failure details for request {}",
        requestId,
        e
      );
    }
  }

  private void applyHeaders(
    HttpExecutionContext ctx,
    WebhookConfiguration webhook,
    HttpRequest.Builder builder
  ) {
    boolean hasContentType = false;
    if (webhook.getHeaders() != null) {
      for (HeaderConfiguration header : webhook.getHeaders()) {
        if (header.getName() != null && header.getValue() != null) {
          String value = ctx
            .getTemplateEngine()
            .evalNow(header.getValue(), String.class);
          builder.header(header.getName(), value);
          if ("Content-Type".equalsIgnoreCase(header.getName())) {
            hasContentType = true;
          }
        }
      }
    }
    if (!hasContentType) {
      builder.header("Content-Type", "application/json");
    }
  }

  private String buildPayload(
    HttpExecutionContext ctx,
    IcapPhase phase,
    byte[] body,
    IcapScanResult result,
    WebhookConfiguration webhook
  ) throws Exception {
    if (
      webhook.getPayloadTemplate() != null &&
      !webhook.getPayloadTemplate().isBlank()
    ) {
      log.debug(
        "ICAP webhook using custom payload template for request {}",
        safeRequestId(ctx)
      );
      return ctx
        .getTemplateEngine()
        .evalNow(webhook.getPayloadTemplate(), String.class);
    }
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put(
      "event",
      "icap.scan." + result.getVerdict().name().toLowerCase()
    );
    payload.put("timestamp", Instant.now().toString());
    payload.put("verdict", result.getVerdict().name());
    payload.put("threatName", result.getThreatName());
    payload.put("message", result.getMessage());
    payload.put("icapStatusCode", result.getIcapStatusCode());
    payload.put(
      "executionMode",
      configuration.getExecutionMode() != null
        ? configuration.getExecutionMode().name()
        : ExecutionMode.SYNCHRONOUS.name()
    );
    payload.put("phase", phase.name());
    payload.put("requestId", ctx.request().id());
    payload.put("method", ctx.request().method().name());
    payload.put("path", ctx.request().path());
    payload.put("host", ctx.request().host());
    payload.put("contentType", ctx.request().headers().get("Content-Type"));
    payload.put("bodyBytes", body != null ? body.length : 0);
    payload.put("bodySha256", sha256(body));
    return MAPPER.writeValueAsString(payload);
  }

  private static String safeRequestId(HttpExecutionContext ctx) {
    try {
      return ctx.request().id();
    } catch (Exception e) {
      return "unknown";
    }
  }

  private static String sha256(byte[] body) {
    if (body == null || body.length == 0) {
      return "";
    }
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(body);
      return HexFormat.of().formatHex(digest);
    } catch (Exception e) {
      return "";
    }
  }
}
