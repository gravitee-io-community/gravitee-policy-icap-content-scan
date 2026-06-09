package io.gravitee.policy.icap.configuration;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class HeaderConfiguration {

  private String name;
  private String value;
}
