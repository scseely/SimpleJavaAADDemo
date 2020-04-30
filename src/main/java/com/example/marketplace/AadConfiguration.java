package com.example.marketplace;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("aad")
@Data
public class AadConfiguration {
    private String clientId;
    private String redirectUriSignin;
    private String secretKey;
    private String tenantId;
}
