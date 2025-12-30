package ee.eesti.authentication.service;

import ee.eesti.authentication.configuration.SsoResolverProperties;
import ee.eesti.authentication.configuration.SsoResolverProperties.Attributes;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.Map.Entry;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class SsoResolver {

  private final SsoResolverProperties ssoResolverProperties;

    public String resolve(HttpServletRequest request) {
        return Optional.ofNullable(ssoResolverProperties.getSso())
                .stream()
                .flatMap(sso -> sso.entrySet().stream())
                .filter(entry -> {
                    var attributes = entry.getValue();
                    return hasMatchByHeader(request, attributes);
                })
                .map(Entry::getKey)
                .findFirst()
                .orElse(ssoResolverProperties.getDefaultSso());
    }

    private boolean hasMatchByHeader(HttpServletRequest request, Attributes attributes) {
        if (attributes.getHeaderName() == null || attributes.getHeaderValue() == null) {
            return false;
        }
        var headerValues = Collections.list(request.getHeaders(attributes.getHeaderName()));
        return headerValues.stream()
                .anyMatch(value -> value.equals(attributes.getHeaderValue()));
    }
}
