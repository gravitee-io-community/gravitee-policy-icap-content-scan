package io.gravitee.policy.icap;

import io.gravitee.gateway.reactive.api.context.HttpExecutionContext;
import io.gravitee.policy.icap.configuration.AsyncOnThreatAction;
import io.gravitee.policy.icap.configuration.IcapContentScanPolicyConfiguration;
import io.gravitee.resource.icap.model.IcapPhase;
import io.gravitee.resource.icap.model.IcapScanResult;
import io.gravitee.resource.icap.model.IcapVerdict;
import java.util.EnumSet;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class IcapAsyncSideEffectsHandler {

  public static final String ATTR_THREAT_DETECTED =
    "icap.async.threat.detected";
  public static final String ATTR_THREAT_NAME = "icap.async.threat.name";

  private final IcapContentScanPolicyConfiguration configuration;

  public void handle(
    HttpExecutionContext ctx,
    IcapPhase phase,
    byte[] body,
    IcapScanResult result
  ) {
    if (result == null) {
      log.debug("ICAP async side effects skipped: scan result is null");
      return;
    }
    log.debug(
      "ICAP async side effects for phase {}: verdict={}",
      phase,
      result.getVerdict()
    );
    switch (result.getVerdict()) {
      case INFECTED -> handleThreat(ctx, phase, result);
      case MODIFIED -> log.debug(
        "ICAP async scan detected modifiable content for phase {} but content was already forwarded",
        phase
      );
      case ERROR -> {
        log.debug(
          "ICAP async scan error for phase {}: {}",
          phase,
          result.getMessage()
        );
        incrementMetric(ctx, "icap.async.scan.error");
      }
      default -> log.debug("ICAP async scan clean for phase {}", phase);
    }
  }

  private void handleThreat(
    HttpExecutionContext ctx,
    IcapPhase phase,
    IcapScanResult result
  ) {
    List<AsyncOnThreatAction> actions = configuration.getAsyncOnThreat();
    if (actions == null || actions.isEmpty()) {
      log.debug(
        "ICAP async threat detected for {} but asyncOnThreat is empty",
        safeRequestId(ctx)
      );
      return;
    }
    EnumSet<AsyncOnThreatAction> actionSet = EnumSet.copyOf(actions);
    log.debug(
      "ICAP async threat handling for {}: actions={}, threat={}",
      safeRequestId(ctx),
      actionSet,
      result.getThreatName() != null
        ? result.getThreatName()
        : result.getMessage()
    );
    if (actionSet.contains(AsyncOnThreatAction.LOG)) {
      log.warn(
        "ICAP async threat detected on {} {} for request {}: {}",
        phase,
        ctx.request().path(),
        ctx.request().id(),
        result.getThreatName() != null
          ? result.getThreatName()
          : result.getMessage()
      );
    }
    if (actionSet.contains(AsyncOnThreatAction.METRIC)) {
      incrementMetric(ctx, "icap.async.threat.detected");
    }
    if (actionSet.contains(AsyncOnThreatAction.CONTEXT_ATTRIBUTE)) {
      ctx.setAttribute(ATTR_THREAT_DETECTED, true);
      if (result.getThreatName() != null) {
        ctx.setAttribute(ATTR_THREAT_NAME, result.getThreatName());
      }
    }
  }

  private void incrementMetric(HttpExecutionContext ctx, String name) {
    ctx.setAttribute("metric." + name, 1L);
  }

  private static String safeRequestId(HttpExecutionContext ctx) {
    try {
      return ctx.request().id();
    } catch (Exception e) {
      return "unknown";
    }
  }
}
