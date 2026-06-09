package io.gravitee.policy.icap.configuration;

import io.gravitee.policy.api.PolicyConfiguration;
import io.gravitee.resource.icap.model.IcapScanMode;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class IcapContentScanPolicyConfiguration implements PolicyConfiguration {

  private String icapResource;
  private ExecutionMode executionMode = ExecutionMode.SYNCHRONOUS;
  private List<AsyncOnThreatAction> asyncOnThreat = new ArrayList<>(
    List.of(
      AsyncOnThreatAction.LOG,
      AsyncOnThreatAction.METRIC,
      AsyncOnThreatAction.CONTEXT_ATTRIBUTE
    )
  );
  private boolean webhookEnabled;
  private List<WebhookTrigger> webhookOn = new ArrayList<>(
    List.of(WebhookTrigger.INFECTED)
  );
  private WebhookConfiguration webhook = new WebhookConfiguration();
  private boolean enableContentModification = false;
  private boolean treatModificationAsClean = true;
  private ModificationParseFailureAction modificationParseFailureAction =
    ModificationParseFailureAction.PASS_ORIGINAL;
  private List<String> modifiableRequestHeaders = new ArrayList<>(
    List.of("Content-Type", "Content-Length", "Content-Disposition")
  );
  private List<String> modifiableResponseHeaders = new ArrayList<>(
    List.of("Content-Type", "Content-Length", "Content-Disposition")
  );
  private IcapScanMode scanMode = IcapScanMode.AUTO;
  private int previewBytes = 4096;
  private int maxBodyBytes = 10 * 1024 * 1024;
  private boolean failClosedOnOversizeBody;
  private boolean detectOnly;
  private boolean failClosedOnIcapError = true;
  private int blockStatusCode = 403;
  private String blockMessage = "Request blocked by ICAP content scan";
  private List<String> forwardedRequestHeaders = new ArrayList<>(
    List.of("Content-Type", "Content-Disposition")
  );
  private List<String> forwardedResponseHeaders = new ArrayList<>(
    List.of("Content-Type", "Content-Disposition")
  );
}
