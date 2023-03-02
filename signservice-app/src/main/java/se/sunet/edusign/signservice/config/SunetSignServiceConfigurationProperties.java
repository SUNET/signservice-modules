package se.sunet.edusign.signservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

/**
 * Configuration properties for Sunet specific extensions for the SignService configuration.
 * 
 * @author Martin Lindström
 */
@ConfigurationProperties("sunet.signservice")
@Data
public class SunetSignServiceConfigurationProperties {  
}
