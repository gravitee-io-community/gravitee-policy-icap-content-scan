package io.gravitee.policy.icap;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.HttpExecutionContext;
import io.gravitee.gateway.reactive.api.policy.Policy;
import io.gravitee.policy.icap.configuration.ExecutionMode;
import io.gravitee.policy.icap.configuration.IcapContentScanPolicyConfiguration;
import io.gravitee.policy.icap.configuration.ModificationParseFailureAction;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.icap.IcapResource;
import io.gravitee.resource.icap.model.IcapPhase;
import io.gravitee.resource.icap.model.IcapScanRequest;
import io.gravitee.resource.icap.model.IcapScanResult;
import io.gravitee.resource.icap.model.IcapVerdict;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.core.Single;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class IcapContentScanPolicy implements Policy {

  public static final String ICAP_THREAT_DETECTED = "ICAP_THREAT_DETECTED";
  public static final String ICAP_SCAN_ERROR = "ICAP_SCAN_ERROR";
  public static final String ICAP_MODIFICATION_PARSE_ERROR =
    "ICAP_MODIFICATION_PARSE_ERROR";
  public static final String ICAP_BODY_LIMIT = "ICAP_BODY_LIMIT";
  public static final String ATTR_THREAT_DETECTED = "icap.threat.detected";
  public static final String ATTR_CONTENT_MODIFIED = "icap.content.modified";

  private final IcapContentScanPolicyConfiguration configuration;
  private final IcapWebhookNotifier webhookNotifier;
  private final IcapAsyncSideEffectsHandler asyncSideEffectsHandler;

  public IcapContentScanPolicy(
    IcapContentScanPolicyConfiguration configuration
  ) {
    this.configuration = configuration;
    this.webhookNotifier = new IcapWebhookNotifier(configuration);
    this.asyncSideEffectsHandler = new IcapAsyncSideEffectsHandler(
      configuration
    );
  }

  @Override
  public String id() {
    return "icap-content-scan";
  }

  @Override
  public Completable onRequest(HttpExecutionContext ctx) {
    return Completable.defer(() -> scanBody(ctx, IcapPhase.REQUEST));
  }

  @Override
  public Completable onResponse(HttpExecutionContext ctx) {
    return Completable.defer(() -> scanBody(ctx, IcapPhase.RESPONSE));
  }

  private Completable scanBody(HttpExecutionContext ctx, IcapPhase phase) {
    if (phase == IcapPhase.REQUEST) {
      return ctx.request().onBody(body -> processBody(ctx, phase, body));
    }
    return ctx.response().onBody(body -> processBody(ctx, phase, body));
  }

  private Maybe<Buffer> processBody(
    HttpExecutionContext ctx,
    IcapPhase phase,
    Maybe<Buffer> maybeBody
  ) {
    return maybeBody
      .defaultIfEmpty(Buffer.buffer())
      .flatMapMaybe(buffer -> {
        byte[] bytes = buffer.getBytes();
        log.debug(
          "ICAP scan processing body for request {} phase {}: {} bytes, executionMode={}, scanMode={}",
          ctx.request().id(),
          phase,
          bytes.length,
          configuration.getExecutionMode(),
          configuration.getScanMode()
        );
        Maybe<Buffer> oversize = validateBodySize(ctx, bytes);
        if (oversize != null) {
          return oversize;
        }

        IcapResource resource = resolveResource(ctx);
        if (resource == null) {
          log.debug(
            "ICAP resource unavailable for request {}: configured name='{}'",
            ctx.request().id(),
            configuration.getIcapResource()
          );
          return failOrPass(
            ctx,
            buffer,
            "ICAP resource '" +
              configuration.getIcapResource() +
              "' is not available"
          );
        }

        if (!IcapPhaseSupport.isScanSupported(resource, phase)) {
          log.debug(
            "ICAP scan skipped for request {}: phase {} requires {} but ICAP OPTIONS advertises {}",
            ctx.request().id(),
            phase,
            IcapPhaseSupport.requiredIcapMethod(phase),
            resource.getOptions() != null
              ? resource.getOptions().getMethods()
              : null
          );
          return Maybe.just(buffer);
        }

        IcapScanRequest scanRequest = IcapScanRequestFactory.build(
          ctx,
          configuration,
          phase,
          bytes
        );
        if (configuration.getExecutionMode() == ExecutionMode.ASYNCHRONOUS) {
          log.debug(
            "ICAP async scan starting for request {} phase {}",
            ctx.request().id(),
            phase
          );
          Completable asyncScan = phase == IcapPhase.REQUEST
            ? resource.scanRequestAsync(scanRequest, result -> {
              log.debug(
                "ICAP async scan completed for request {} phase {}: verdict={}",
                ctx.request().id(),
                phase,
                result != null ? result.getVerdict() : null
              );
              asyncSideEffectsHandler.handle(ctx, phase, bytes, result);
              webhookNotifier.maybeNotify(ctx, phase, bytes, result);
            })
            : resource.scanResponseAsync(scanRequest, result -> {
              log.debug(
                "ICAP async scan completed for request {} phase {}: verdict={}",
                ctx.request().id(),
                phase,
                result != null ? result.getVerdict() : null
              );
              asyncSideEffectsHandler.handle(ctx, phase, bytes, result);
              webhookNotifier.maybeNotify(ctx, phase, bytes, result);
            });
          asyncScan.subscribe();
          return Maybe.just(buffer);
        }

        log.debug(
          "ICAP sync scan starting for request {} phase {}",
          ctx.request().id(),
          phase
        );

        Single<IcapScanResult> scan = phase == IcapPhase.REQUEST
          ? resource.scanRequest(scanRequest)
          : resource.scanResponse(scanRequest);
        return scan.flatMapMaybe(result ->
          applySyncResult(ctx, phase, buffer, result)
        );
      });
  }

  private Maybe<Buffer> applySyncResult(
    HttpExecutionContext ctx,
    IcapPhase phase,
    Buffer original,
    IcapScanResult result
  ) {
    log.debug(
      "ICAP sync scan completed for request {} phase {}: verdict={}, icapStatus={}",
      ctx.request().id(),
      phase,
      result.getVerdict(),
      result.getIcapStatusCode()
    );
    webhookNotifier.maybeNotify(ctx, phase, original.getBytes(), result);
    return switch (result.getVerdict()) {
      case CLEAN -> Maybe.just(original);
      case INFECTED -> handleInfected(ctx, original, result);
      case MODIFIED -> handleModified(ctx, phase, original, result);
      case ERROR -> failOrPass(
        ctx,
        original,
        result.getMessage() != null ? result.getMessage() : "ICAP scan failed"
      );
    };
  }

  private Maybe<Buffer> handleInfected(
    HttpExecutionContext ctx,
    Buffer original,
    IcapScanResult result
  ) {
    ctx.setAttribute(ATTR_THREAT_DETECTED, true);
    if (configuration.isDetectOnly()) {
      log.debug(
        "ICAP threat detected for request {} (detect only): {}",
        ctx.request().id(),
        result.getThreatName()
      );
      return Maybe.just(original);
    }
    log.debug(
      "ICAP threat detected for request {}: blocking with status {}",
      ctx.request().id(),
      configuration.getBlockStatusCode()
    );
    String message = configuration.getBlockMessage();
    if (result.getThreatName() != null) {
      message = message + " (" + result.getThreatName() + ")";
    }
    return ctx.interruptBodyWith(
      new ExecutionFailure(configuration.getBlockStatusCode())
        .key(ICAP_THREAT_DETECTED)
        .message(message)
    );
  }

  private Maybe<Buffer> handleModified(
    HttpExecutionContext ctx,
    IcapPhase phase,
    Buffer original,
    IcapScanResult result
  ) {
    if (!configuration.isEnableContentModification()) {
      log.debug(
        "ICAP content modification disabled for request {}: treatModificationAsClean={}",
        ctx.request().id(),
        configuration.isTreatModificationAsClean()
      );
      if (!configuration.isTreatModificationAsClean()) {
        return handleInfected(ctx, original, result);
      }
      return Maybe.just(original);
    }
    if (result.getModifiedBody() == null) {
      if (
        configuration.getModificationParseFailureAction() ==
        ModificationParseFailureAction.FAIL
      ) {
        log.debug(
          "ICAP modification parse failed for request {}: failing closed",
          ctx.request().id()
        );
        return ctx.interruptBodyWith(
          new ExecutionFailure(HttpStatusCode.INTERNAL_SERVER_ERROR_500)
            .key(ICAP_MODIFICATION_PARSE_ERROR)
            .message("Unable to parse ICAP modified content")
        );
      }
      log.debug(
        "ICAP modification response could not be parsed for request {}; forwarding original content",
        ctx.request().id()
      );
      return Maybe.just(original);
    }
    log.debug(
      "ICAP applying modified content for request {} phase {}: {} bytes",
      ctx.request().id(),
      phase,
      result.getModifiedBody().length
    );
    applyModifiedHeaders(
      phase == IcapPhase.REQUEST
        ? ctx.request().headers()
        : ctx.response().headers(),
      result,
      phase
    );
    ctx.setAttribute(ATTR_CONTENT_MODIFIED, true);
    return Maybe.just(Buffer.buffer(result.getModifiedBody()));
  }

  private void applyModifiedHeaders(
    HttpHeaders headers,
    IcapScanResult result,
    IcapPhase phase
  ) {
    List<String> allowlist = phase == IcapPhase.REQUEST
      ? configuration.getModifiableRequestHeaders()
      : configuration.getModifiableResponseHeaders();
    Map<String, String> modified = result.getModifiedHeaders();
    if (headers == null || modified == null || allowlist == null) {
      return;
    }
    for (String allowed : allowlist) {
      for (Map.Entry<String, String> entry : modified.entrySet()) {
        if (allowed.equalsIgnoreCase(entry.getKey())) {
          headers.set(allowed, entry.getValue());
          log.debug(
            "ICAP updated {} header for phase {}: {}",
            allowed,
            phase,
            entry.getValue()
          );
        }
      }
    }
  }

  private Maybe<Buffer> validateBodySize(
    HttpExecutionContext ctx,
    byte[] bytes
  ) {
    if (bytes.length <= configuration.getMaxBodyBytes()) {
      return null;
    }
    if (configuration.isFailClosedOnOversizeBody()) {
      log.debug(
        "ICAP body size limit exceeded for request {}: {} bytes > maxBodyBytes={}; failing closed",
        ctx.request().id(),
        bytes.length,
        configuration.getMaxBodyBytes()
      );
      return ctx.interruptBodyWith(
        new ExecutionFailure(HttpStatusCode.REQUEST_ENTITY_TOO_LARGE_413)
          .key(ICAP_BODY_LIMIT)
          .message("Body exceeds ICAP scan limit")
      );
    }
    log.debug(
      "ICAP body size limit exceeded for request {}: {} bytes > maxBodyBytes={}; skipping scan",
      ctx.request().id(),
      bytes.length,
      configuration.getMaxBodyBytes()
    );
    return Maybe.just(Buffer.buffer(bytes));
  }

  private Maybe<Buffer> failOrPass(
    HttpExecutionContext ctx,
    Buffer original,
    String message
  ) {
    if (configuration.isFailClosedOnIcapError()) {
      log.debug(
        "ICAP scan issue for request {}: failing closed: {}",
        ctx.request().id(),
        message
      );
      return ctx.interruptBodyWith(
        new ExecutionFailure(HttpStatusCode.INTERNAL_SERVER_ERROR_500)
          .key(ICAP_SCAN_ERROR)
          .message(message)
      );
    }
    log.debug(
      "ICAP scan issue for request {} ignored (fail open): {}",
      ctx.request().id(),
      message
    );
    return Maybe.just(original);
  }

  private IcapResource resolveResource(HttpExecutionContext ctx) {
    if (
      configuration.getIcapResource() == null ||
      configuration.getIcapResource().isBlank()
    ) {
      return null;
    }
    String resourceName = ctx
      .getTemplateEngine()
      .evalNow(configuration.getIcapResource(), String.class);
    IcapResource resource = ctx
      .getComponent(ResourceManager.class)
      .getResource(resourceName, IcapResource.class);
    log.debug(
      "ICAP resolved resource for request {}: name='{}', available={}",
      ctx.request().id(),
      resourceName,
      resource != null
    );
    return resource;
  }
}
