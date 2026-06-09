package io.gravitee.policy.icap.configuration;

import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class WebhookConfiguration {

  private String url;
  private String method = "POST";
  private int timeoutMs = 5000;
  private int retryCount = 1;
  private String payloadTemplate;
  private List<HeaderConfiguration> headers = new ArrayList<>();
}
