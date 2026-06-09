package io.gravitee.policy.icap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import io.gravitee.common.http.HttpMethod;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.context.HttpExecutionContext;
import io.gravitee.gateway.reactive.api.context.HttpRequest;
import io.gravitee.policy.icap.configuration.IcapContentScanPolicyConfiguration;
import io.gravitee.resource.icap.model.IcapPhase;
import io.gravitee.resource.icap.model.IcapScanMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IcapScanRequestFactoryTest {

  @Mock
  private HttpExecutionContext ctx;

  @Mock
  private HttpRequest request;

  @Test
  void shouldBuildRequestScanPayload() {
    IcapContentScanPolicyConfiguration configuration =
      new IcapContentScanPolicyConfiguration();
    configuration.setScanMode(IcapScanMode.AUTO);
    configuration.setPreviewBytes(2048);
    configuration.setForwardedRequestHeaders(java.util.List.of("Content-Type"));

    HttpHeaders headers = HttpHeaders.create();
    headers.set("Content-Type", "application/json");

    when(ctx.request()).thenReturn(request);
    when(request.method()).thenReturn(HttpMethod.POST);
    when(request.path()).thenReturn("/upload");
    when(request.host()).thenReturn("api.example.com");
    when(request.headers()).thenReturn(headers);

    var scanRequest = IcapScanRequestFactory.build(
      ctx,
      configuration,
      IcapPhase.REQUEST,
      "{\"file\":true}".getBytes()
    );

    assertThat(scanRequest.getPhase()).isEqualTo(IcapPhase.REQUEST);
    assertThat(scanRequest.getScanMode()).isEqualTo(IcapScanMode.AUTO);
    assertThat(scanRequest.getPreviewBytes()).isEqualTo(2048);
    assertThat(scanRequest.getHeaders()).containsEntry(
      "Content-Type",
      "application/json"
    );
  }
}
