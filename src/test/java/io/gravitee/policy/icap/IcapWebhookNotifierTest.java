package io.gravitee.policy.icap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.sun.net.httpserver.HttpServer;
import io.gravitee.common.http.HttpMethod;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.context.HttpExecutionContext;
import io.gravitee.gateway.reactive.api.context.HttpRequest;
import io.gravitee.policy.icap.configuration.ExecutionMode;
import io.gravitee.policy.icap.configuration.IcapContentScanPolicyConfiguration;
import io.gravitee.policy.icap.configuration.WebhookConfiguration;
import io.gravitee.policy.icap.configuration.WebhookTrigger;
import io.gravitee.resource.icap.model.IcapPhase;
import io.gravitee.resource.icap.model.IcapScanResult;
import io.gravitee.resource.icap.model.IcapVerdict;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IcapWebhookNotifierTest {

  @Mock
  private HttpExecutionContext ctx;

  @Mock
  private HttpRequest request;

  @Mock
  private TemplateEngine templateEngine;

  private HttpServer httpServer;
  private final AtomicReference<String> receivedBody = new AtomicReference<>();

  @BeforeEach
  void setUp() throws IOException {
    httpServer = HttpServer.create(new InetSocketAddress(0), 0);
    httpServer.createContext("/hook", exchange -> {
      receivedBody.set(
        new String(
          exchange.getRequestBody().readAllBytes(),
          StandardCharsets.UTF_8
        )
      );
      exchange.sendResponseHeaders(204, -1);
      exchange.close();
    });
    httpServer.start();
  }

  @AfterEach
  void tearDown() {
    if (httpServer != null) {
      httpServer.stop(0);
    }
  }

  @Test
  void shouldPostDefaultWebhookPayloadWhenEnabled() {
    int port = httpServer.getAddress().getPort();
    IcapContentScanPolicyConfiguration configuration =
      new IcapContentScanPolicyConfiguration();
    configuration.setWebhookEnabled(true);
    configuration.setWebhookOn(List.of(WebhookTrigger.INFECTED));
    configuration.setExecutionMode(ExecutionMode.SYNCHRONOUS);
    WebhookConfiguration webhook = new WebhookConfiguration();
    webhook.setUrl("http://127.0.0.1:" + port + "/hook");
    configuration.setWebhook(webhook);

    stubRequestContext(webhook.getUrl());

    IcapScanResult result = IcapScanResult.builder()
      .verdict(IcapVerdict.INFECTED)
      .threatName("Eicar-Signature")
      .build();

    new IcapWebhookNotifier(configuration).maybeNotify(
      ctx,
      IcapPhase.REQUEST,
      "abc".getBytes(),
      result
    );

    assertThat(receivedBody.get()).contains("icap.scan.infected");
    assertThat(receivedBody.get()).contains("Eicar-Signature");
    assertThat(receivedBody.get()).contains("req-42");
    assertThat(receivedBody.get()).contains("SYNCHRONOUS");
  }

  @Test
  void shouldNotSendWhenWebhookDisabled() {
    IcapContentScanPolicyConfiguration configuration =
      new IcapContentScanPolicyConfiguration();
    configuration.setWebhookEnabled(false);
    configuration.setWebhookOn(List.of(WebhookTrigger.INFECTED));
    WebhookConfiguration webhook = new WebhookConfiguration();
    webhook.setUrl("http://127.0.0.1:9999/hook");
    configuration.setWebhook(webhook);

    new IcapWebhookNotifier(configuration).maybeNotify(
      ctx,
      IcapPhase.REQUEST,
      "abc".getBytes(),
      IcapScanResult.builder().verdict(IcapVerdict.INFECTED).build()
    );

    assertThat(receivedBody.get()).isNull();
  }

  @Test
  void shouldRespectWebhookOnTriggers() {
    int port = httpServer.getAddress().getPort();
    IcapContentScanPolicyConfiguration configuration =
      new IcapContentScanPolicyConfiguration();
    configuration.setWebhookEnabled(true);
    configuration.setWebhookOn(
      List.of(WebhookTrigger.CLEAN, WebhookTrigger.ERROR)
    );
    WebhookConfiguration webhook = new WebhookConfiguration();
    webhook.setUrl("http://127.0.0.1:" + port + "/hook");
    configuration.setWebhook(webhook);

    stubRequestContext(webhook.getUrl());

    new IcapWebhookNotifier(configuration).maybeNotify(
      ctx,
      IcapPhase.REQUEST,
      "abc".getBytes(),
      IcapScanResult.clean()
    );

    assertThat(receivedBody.get()).contains("icap.scan.clean");

    receivedBody.set(null);

    new IcapWebhookNotifier(configuration).maybeNotify(
      ctx,
      IcapPhase.REQUEST,
      "abc".getBytes(),
      IcapScanResult.builder()
        .verdict(IcapVerdict.INFECTED)
        .threatName("Eicar")
        .build()
    );

    assertThat(receivedBody.get()).isNull();
  }

  @Test
  void shouldMapVerdictsToTriggers() {
    assertThat(
      IcapWebhookNotifier.mapVerdictToTrigger(IcapVerdict.CLEAN)
    ).isEqualTo(WebhookTrigger.CLEAN);
    assertThat(
      IcapWebhookNotifier.mapVerdictToTrigger(IcapVerdict.MODIFIED)
    ).isEqualTo(WebhookTrigger.MODIFIED);
  }

  private void stubRequestContext(String url) {
    HttpHeaders headers = HttpHeaders.create();
    headers.set("Content-Type", "text/plain");

    when(ctx.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.evalNow(eq(url), eq(String.class))).thenReturn(url);
    when(ctx.request()).thenReturn(request);
    when(request.id()).thenReturn("req-42");
    when(request.method()).thenReturn(HttpMethod.POST);
    when(request.path()).thenReturn("/files");
    when(request.host()).thenReturn("api.example.com");
    when(request.headers()).thenReturn(headers);
  }
}
