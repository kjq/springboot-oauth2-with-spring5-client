## Mixing old style Spring Security @EnableAuthorizationServer and @EnableResourceServer) with new style Spring Security 5 clients

We wanted to provide an Authorization Server using OAuth2 and JWT.  

We decided to use Spring because of the integration with the rest of the security mechanisms already available.  Other options 
we strongly considered for ease were Apache CXF (it just works) OAuth2 implementation and Shiro with manually configured filters 
(has not been updated in ages but we will end up using for permissions).

For clients, we wanted to take advantage of the new Spring Security 5 APIs.  They communicate with the Authorization server either 
using OAuth2 proper or JWT.

The approach below allows for:
- Authenticating through an OAuth2 login
- Authenticating through POSTman against the API directly using a Bearer token

This is not complete and very rough but it works and covers all of the scenarios...

### Authorization Server and Resource Server using Spring Boot Security (old Authorization/Resource style)

Spring Authorization (@EnableAuthorizationServer) and Resource (@EnableResource) server using the old style API (shim or whatever
you want to call it) because it has not been updated for the new Spring Security 5 API fully.

In order for newer clients to take use this server easily we had to additionally expose the "well known" JSON 
(http://localhost:8080/.well-known/jwks.json) with the public key so that new style Spring Security5/OAuth2 clients 
could access it.

One thing to note was I wrestled with the order of the filters so I explicitly defined them using the @Order annotation.

```
import static com.google.common.collect.Lists.newArrayList;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerSecurityConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import javax.inject.Inject;
import java.security.KeyPair;

@Slf4j
@Configuration
public class OAuthServerConfiguration
{
    @Inject
    void globalUserDetails(final AuthenticationManagerBuilder auth, PasswordEncoder passwordEncoder) throws Exception
    {
        auth.inMemoryAuthentication()
            .withUser("user")
            .password(passwordEncoder.encode("pass"))
            .roles("USER").and()
            .withUser("admin")
            .password(passwordEncoder.encode("admin"))
            .roles("ADMIN");
    }

    @Bean
    JwtAccessTokenConverter jwtAccessTokenConverter(final KeyPair keyPair)
    {
        final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setKeyPair(keyPair);
        return converter;
    }

    @Bean
    AuthenticationProvider jwtAuthenticationProvider()
    {
        return new JwtAuthenticationProvider();
    }

    @Bean
    KeyPair jwtKeyPair()
    {
        final KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
            new ClassPathResource(KEY_STORE),
            PRIVATE_KEY_SECRET.toCharArray());
        return keyStoreKeyFactory.getKeyPair(PRIVATE_KEY_ALIAS);
    }

    @Bean
    TokenStore jwtTokenStore(JwtAccessTokenConverter accessTokenConverter)
    {
        return new JwtTokenStore(accessTokenConverter);
    }

    @Bean
    @Primary
    DefaultTokenServices oauthTokenServices(final TokenStore tokenStore)
    {
        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore);
        return defaultTokenServices;
    }

    @Order(2)
    @Configuration
    @EnableResourceServer
    @Import(AuthorizationServerEndpointsConfiguration.class)
    protected static class AuthorizationServerConfiguration extends AuthorizationServerSecurityConfiguration
    {
    }

    @Configuration
    protected static class OAuthAuthorizationConfiguration extends AuthorizationServerConfigurerAdapter
    {
        @Inject
        private AuthenticationManager authenticationManager;

        @Inject
        private AccessTokenConverter accessTokenConverter;

        @Inject
        private TokenStore tokenStore;

        @Inject
        private PasswordEncoder passwordEncoder;

        @Override
        public void configure(final ClientDetailsServiceConfigurer clients) throws Exception
        {
            clients.inMemory()
                   .withClient("foobar")
                   .authorities("ROLE_TEST")
                   .resourceIds("audience")
                   .secret(passwordEncoder.encode("secret"))
                   .autoApprove(false)
                   .accessTokenValiditySeconds(3600)
                   .refreshTokenValiditySeconds(2592000)
                   .authorizedGrantTypes(
                       "implicit",
                       "password",
                       "authorization_code",
                       "client_credentials",
                       "refresh_token")
                   .scopes(
                       "foo",
                       "read",
                       "write")
                   .redirectUris(
                       "http://localhost:8080/api/test",
                       "http://localhost:8090/api/test",
                       "http://localhost:8080/authorize/oauth2/code/my-client",
                       "http://localhost:8090/login/oauth2/code/my-client",
                       "http://localhost:8080/login/oauth2/code/my-client");
        }

        @Override
        public void configure(final AuthorizationServerSecurityConfigurer oauthServer)
        {
            oauthServer
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients();
        }

        @Override
        public void configure(final AuthorizationServerEndpointsConfigurer endpoints)
        {
            //Create our token enhancer chaing
            final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
            tokenEnhancerChain.setTokenEnhancers(newArrayList(
                new OAuthTokenEnhancer(),
                (TokenEnhancer)accessTokenConverter));

            //Configure the endpoints
            endpoints
                .tokenStore(tokenStore)
                .tokenEnhancer(tokenEnhancerChain)
                .authenticationManager(authenticationManager);
        }
    }

    @Configuration
    protected static class OAuthResourceConfiguration extends ResourceServerConfigurerAdapter
    {
        @Inject
        private AuthenticationManager authenticationManager;

        @Inject
        private TokenStore tokenStore;

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) throws Exception
        {
            resources.tokenStore(tokenStore)
                     .authenticationManager(this.authenticationManager);
        }
    }

    @Order(1)
    @Configuration
    @EnableWebSecurity
    protected static class OAuthWebSecurityConfig extends WebSecurityConfigurerAdapter
    {
        @Inject
        private AuthenticationProvider jwtAuthenticationProvider;

        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean() throws Exception
        {
            return super.authenticationManagerBean();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception
        {
            auth.authenticationProvider(jwtAuthenticationProvider);
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception
        {
            http.requestMatchers()
                .antMatchers("/login",
                             "/logout",
                             "/oauth/authorize",
                             "/oauth/confirm_access",
                             "/favicon.ico",
                             WELL_KNOWN_URI)
                .and()
                .authorizeRequests()
                .antMatchers("/login",
                             "/logout",
                             "/oauth/authorize",
                             "/oauth/confirm_access",
                             "/favicon.ico",
                             WELL_KNOWN_URI).permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll()
                .and()
                .logout().permitAll();
        }
    }
}
```

### JWK Set "WellKnown" Endpoint
New Spring OAuth clients need the `jwk-set-uri` property set in order to access this. 
It exposes the public key to the clients.

```
@FrameworkEndpoint
class JksSetController
{
    @Inject
    private KeyPair keyPair;

    @ResponseBody
    @GetMapping(WELL_KNOWN_URI)
    public Map<String, Object> getKey(Principal principal)
    {
        final RSAPublicKey rsaPublicKey = (RSAPublicKey)this.keyPair.getPublic();
        final RSAKey key = new RSAKey.Builder(rsaPublicKey)
            .keyUse(new KeyUse("sig"))
            .algorithm(new Algorithm("RS256"))
            .build();
        return new JWKSet(key).toJSONObject();
    }
}
```

### JWT Authentication Provider to receive the token on the Authorization side
I needed to create and inject a custom authentication provider to understand the JWT token coming in from the client.
At this point, the intent is to get any pertinent details and return them back through the endpoint (if needed).  When
using the JWT by itself we don't even need (or make) any call as everything is self-contained.

```
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class JwtAuthenticationProvider implements AuthenticationProvider
{

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException
    {
        final UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
            authentication.getPrincipal(),
            authentication.getCredentials(),
            null);
        return token;
    }

    @Override
    public boolean supports(Class<?> authentication)
    {
        return UsernamePasswordAuthenticationToken.class.equals(authentication) ||
            PreAuthenticatedAuthenticationToken.class.equals(authentication);
    }
}
```

### OAuth2 Client, Login, and Resource Server (using new Spring Security 5 style)

```
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Slf4j
@Configuration
public class OAuthClientConfiguration extends WebSecurityConfigurerAdapter
{
    @Override
    public void configure(final HttpSecurity http) throws Exception
    {
            http.csrf().disable()
                .cors()
                .and()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .and()
                .oauth2Client()
                .and()
                .oauth2ResourceServer()
                .jwt();

            log.info("Enabled authorized requests...");
    }
}
```

#### OAuth2 Client, Login, and Resource Configuration (using new Spring Security 5 style)

```
  security:

    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: http://localhost:8080/.well-known/jwks.json

      client:
        registration:
          my-client:
            provider: my-provider
            client-id: foobar
            client-secret: secret
            client-name: My Client
            client-authentication-method: basic
            redirect-uri-template: '{baseUrl}/{action}/oauth2/code/{registrationId}'
            authorization-grant-type: authorization_code

        provider:
          my-provider:
            authorization-uri: http://localhost:8080/oauth/authorize
            token-uri: http://localhost:8080/oauth/token
            jwk-set-uri: http://localhost:8080
            user-info-uri: http://localhost:8080/userinfo
            user-info-authentication-method: header
            user-name-attribute: name
```

### cURL commands from POSTMan

Client Credentials Grant
```
curl -X POST \
  'http://foobar:secret@localhost:8080/oauth/token?grant_type=client_credentials' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'cache-control: no-cache'
```

Password Grant
```
curl -X POST \
  'http://foobar:secret@localhost:8080/oauth/token?grant_type=password&username=user&password=pass' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'cache-control: no-cache' \
```

Implicit Grant
```
curl -X GET \
  'http://localhost:8080/oauth/authorize?client_id=foobar&grant_type=implicit&response_type=token&redirect_uri=http://localhost:8080/' \
  -H 'Content-Type: application/json' \
  -H 'cache-control: no-cache'
```

Test Call using Bearer
```
curl -X GET \
  http://localhost:8090/api/test \
  -H 'Authorization: Bearer {TOKEN}' \
  -H 'cache-control: no-cache'
```

### POM Dependencies
Using the latest Spring Boot (at the time): **2.1.3.RELEASE**

Authorization Server (also includes Resource dependencies below as-well)
```
 <dependency>
    <groupId>org.springframework.security.oauth.boot</groupId>
    <artifactId>spring-security-oauth2-autoconfigure</artifactId>
</dependency>
```

Resource Server (client)
```
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-client</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-resource-server</artifactId>
</dependency>
```
