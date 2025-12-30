package ee.eesti.authentication.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;

@Configuration
public class RedisConfig {

    @Bean
    public RedisTemplate<String, OidcSessionInformation> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisSerializer<Object> serializer = new JdkSerializationRedisSerializer(this.getClass().getClassLoader());

        RedisTemplate<String, OidcSessionInformation> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(RedisSerializer.string());
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(RedisSerializer.string());
        template.setHashValueSerializer(serializer);

        return template;
    }
}