package io.gravitee.policy.icap;

import static org.assertj.core.api.Assertions.assertThat;

import io.gravitee.policy.icap.configuration.IcapContentScanPolicyConfiguration;
import org.junit.jupiter.api.Test;

class IcapContentScanPolicyTest {

  @Test
  void shouldExposePolicyId() {
    IcapContentScanPolicy policy = new IcapContentScanPolicy(
      new IcapContentScanPolicyConfiguration()
    );
    assertThat(policy.id()).isEqualTo("icap-content-scan");
  }
}
