package io.gravitee.policy.icap;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import io.gravitee.gateway.reactive.api.context.HttpExecutionContext;
import io.gravitee.policy.icap.configuration.AsyncOnThreatAction;
import io.gravitee.policy.icap.configuration.IcapContentScanPolicyConfiguration;
import io.gravitee.resource.icap.model.IcapPhase;
import io.gravitee.resource.icap.model.IcapScanResult;
import io.gravitee.resource.icap.model.IcapVerdict;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IcapAsyncSideEffectsHandlerTest {

  @Mock
  private HttpExecutionContext ctx;

  @Test
  void shouldSetContextAttributesOnAsyncThreat() {
    IcapContentScanPolicyConfiguration configuration =
      new IcapContentScanPolicyConfiguration();
    configuration.setAsyncOnThreat(
      List.of(AsyncOnThreatAction.CONTEXT_ATTRIBUTE)
    );

    IcapAsyncSideEffectsHandler handler = new IcapAsyncSideEffectsHandler(
      configuration
    );
    IcapScanResult result = IcapScanResult.builder()
      .verdict(IcapVerdict.INFECTED)
      .threatName("Eicar-Signature")
      .build();

    handler.handle(ctx, IcapPhase.REQUEST, "test".getBytes(), result);

    verify(ctx).setAttribute(
      IcapAsyncSideEffectsHandler.ATTR_THREAT_DETECTED,
      true
    );
    verify(ctx).setAttribute(
      IcapAsyncSideEffectsHandler.ATTR_THREAT_NAME,
      "Eicar-Signature"
    );
  }

  @Test
  void shouldNotHandleCleanVerdict() {
    IcapContentScanPolicyConfiguration configuration =
      new IcapContentScanPolicyConfiguration();
    configuration.setAsyncOnThreat(List.of(AsyncOnThreatAction.LOG));

    IcapAsyncSideEffectsHandler handler = new IcapAsyncSideEffectsHandler(
      configuration
    );

    handler.handle(
      ctx,
      IcapPhase.REQUEST,
      "test".getBytes(),
      IcapScanResult.clean()
    );

    verifyNoInteractions(ctx);
  }
}
