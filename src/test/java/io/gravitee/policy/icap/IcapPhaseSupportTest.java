package io.gravitee.policy.icap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import io.gravitee.resource.icap.IcapResource;
import io.gravitee.resource.icap.model.IcapOptions;
import io.gravitee.resource.icap.model.IcapPhase;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IcapPhaseSupportTest {

  @Mock
  private IcapResource resource;

  @Test
  void shouldMapPhaseToIcapMethod() {
    assertThat(
      IcapPhaseSupport.requiredIcapMethod(IcapPhase.REQUEST)
    ).isEqualTo("REQMOD");
    assertThat(
      IcapPhaseSupport.requiredIcapMethod(IcapPhase.RESPONSE)
    ).isEqualTo("RESPMOD");
  }

  @Test
  void shouldAllowScanWhenOptionsAdvertiseMethod() {
    when(resource.getOptions()).thenReturn(
      IcapOptions.builder().methods(Set.of("REQMOD", "RESPMOD")).build()
    );

    assertThat(
      IcapPhaseSupport.isScanSupported(resource, IcapPhase.REQUEST)
    ).isTrue();
    assertThat(
      IcapPhaseSupport.isScanSupported(resource, IcapPhase.RESPONSE)
    ).isTrue();
  }

  @Test
  void shouldSkipScanWhenOptionsDoNotAdvertiseMethod() {
    when(resource.getOptions()).thenReturn(
      IcapOptions.builder().methods(Set.of("REQMOD")).build()
    );

    assertThat(
      IcapPhaseSupport.isScanSupported(resource, IcapPhase.REQUEST)
    ).isTrue();
    assertThat(
      IcapPhaseSupport.isScanSupported(resource, IcapPhase.RESPONSE)
    ).isFalse();
  }

  @Test
  void shouldAllowScanWhenOptionsMethodsUnknown() {
    when(resource.getOptions()).thenReturn(IcapOptions.builder().build());

    assertThat(
      IcapPhaseSupport.isScanSupported(resource, IcapPhase.REQUEST)
    ).isTrue();
    assertThat(
      IcapPhaseSupport.isScanSupported(resource, IcapPhase.RESPONSE)
    ).isTrue();
  }
}
