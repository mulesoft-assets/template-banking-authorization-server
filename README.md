# Template Banking Authorization Server

+ [License Agreement](#licenseagreement)
+ [Use Case](#usecase)
+ [Considerations](#considerations)
	* [APIs security considerations](#apissecurityconsiderations)
+ [Run it!](#runit)
	* [Running on premise](#runonopremise)
	* [Running on Studio](#runonstudio)
	* [Running on Mule ESB stand alone](#runonmuleesbstandalone)
	* [Running on CloudHub](#runoncloudhub)
	* [Deploying your Anypoint Template on CloudHub](#deployingyouranypointtemplateoncloudhub)
	* [Applying policies on CloudHub](#applyingpolicies)
	* [Properties to be configured (With examples)](#propertiestobeconfigured)

# License Agreement <a name="licenseagreement"/>
Note that using this template is subject to the conditions of this [License Agreement](AnypointTemplateLicense.pdf).
Please review the terms of the license before downloading and using this template. In short, you are allowed to use the template for free with Mule ESB Enterprise Edition, CloudHub, or as a trial in Anypoint Studio.

# Use Case <a name="usecase"/>


This API serves as an OAuth 2.0 Authorization server for the Banking catalyst. This API issues access tokens for the banking Catalyst Resource servers (AISP and PISP).

# Considerations <a name="considerations"/>

To make this Anypoint Template run, there are certain preconditions that must be considered. **Failing to do so could lead to unexpected behavior of the template.**

## APIs security considerations <a name="apissecurityconsiderations"/>

This Experience API is meant to be deployed to CloudHub and managed using the API Platform Manager.

Only registered clients can have access tokens issued for them. In order to register the client application, the API must be defined in Anypoint Platform's API Manager.  API Autodiscovery configuration properties must be filled correctly to point to the defined API. Public portal created via API Manager can be used to register consuming applications, those will have client_id and client_secret generated. The Anypoint Platform client database will be used to construct the access tokens.

The project extends the [Mule OAuth 2.0 Service Provider](https://docs.mulesoft.com/api-manager/oauth-service-provider-reference) with custom token generation strategy.

Access tokens are generated in signed and encrypted JWT form. Consuming application can implement the verification itself or use a [policy](https://github.com/mulesoft/template-banking-authorization-policy).

User identity is verified using external identity service providing user credentials on the authorization  endpoint.


### Exposing external endpoints with HTTPS
+ It is meant to be consumed by third party applications using HTTPS

# Run it! <a name="runit"/>
Simple steps to get AISP Experience API running.
See below.

## Running on premise <a name="runonopremise"/>
In this section we detail the way you should run your Anypoint Template on your computer.


### Where to Download Anypoint Studio and Mule ESB
First thing to know if you are a newcomer to Mule is where to get the tools.

+ You can download Anypoint Studio from this [location](https://www.mulesoft.com/lp/dl/studio)
+ You can download Mule runtime from this [location](https://www.mulesoft.com/platform/mule)

### Importing an Anypoint Template into Studio
Anypoint Studio offers several ways to import a project into the workspace, for instance:

+ Anypoint Studio Project from a file system
+ Packaged Mule application (.jar)

You can find a detailed description on how to do so in this [documentation page](https://docs.mulesoft.com/).

### Running on Studio <a name="runonstudio"/>
Once you have imported you Anypoint Template into Anypoint Studio you need to follow these steps to run it:

+ Locate the properties file `mule.dev.properties`, in src/main/resources
+ Complete all the properties required as per the examples in the section [Properties to be configured](#propertiestobeconfigured)
+ Once that is done, right click the Anypoint Template project folder
+ Hover your mouse over `"Run as"`
+ Click `"Mule Application (configure)"`
+ Inside the dialog, select Environment and set the variable `"mule.env"` to the value `"dev"`
+ Click `"Run"`

### Running on Mule ESB stand alone <a name="runonmuleesbstandalone"/>
Complete all properties in one of the property files, for example in [mule.prod.properties](../master/src/main/resources/mule.prod.properties) and run your app with the corresponding environment variable to use it. To follow the example, this will be `mule.env=prod`.

## Running on CloudHub <a name="runoncloudhub"/>
While [creating your application on CloudHub](https://docs.mulesoft.com/runtime-manager/) (Or you can do it later as a next step), you need to go to Deployment > Advanced to set all environment variables detailed in **Properties to be configured** as well as the **mule.env**.
Follow other steps defined [here](#runonpremise) and once your app is all set and started, there is no need to do anything else.

### Deploying your Anypoint Template on CloudHub <a name="deployingyouranypointtemplateoncloudhub"/>
Studio provides an easy way to deploy your template directly to CloudHub, for the specific steps to do so check this [link](https://docs.mulesoft.com/runtime-manager/deployment-strategies)

### Applying policies on CloudHub <a name="applyingpolicies"/>
When a Mule application is deployed using the Mule 4.1.3+ Runtime, the API Manager allows you to dynamically apply different policies that can be used for securing the application, among many other things. More information can be found in [API Manager policies documentation](https://docs.mulesoft.com/api-manager/using-policies)

## Properties to be configured (With examples) <a name="propertiestobeconfigured"/>
To use this Mule Anypoint Template you need to configure properties (Credentials, configurations, etc.) either in properties file or in CloudHub as Environment Variables.

Detailed list with examples:

**HTTP Listener Config**
+ https.port `8082`

**API Properties**
+ anypoint.platform.client_id `112ac8s8f02dff0286234bbca11256`
+ anypoint.platform.client_secret `FF1812BC1951A48FC12378DA12CC75 `
+ anypoint.platform.client_name `Client name`
+ api.name `bank-auth-server`
+ api.version `2.0`

**JWT Tokens**
+ jwt.issuer `https://mybank.example.com`
+ jwt.public.keys.url `https://mybank.example.com/api/.well-known/jwks.json`
+ jwt.signing.key.path `keys/rsa-key.jwk`
+ jwt.encryption.key.path `keys/aes-key.jwk`
+ jwt.public.keys.path `keys/jwks.json`
+ jwt.resource.path `mule/apps`

**Signing algorithm**
+ jwt.signing.algorithm `RS256` or `RS384` or `RS512`

**Encryption algorithm**
+ jwt.encryption.algorithm `A128GCM` or `A256GCM`

**Keystore**
+ key.store.password `keyPa$$w0rd`
+ key.store.key.password `key$torePass`
+ key.store.path `keystore.jks`

**HTTP External Service**
+ http.external.service.host `identity-service.example.com`
+ http.external.service.port `443`
+ http.external.service.path `/`

**HTTP External Service authorization URL (protocol://host:port/authPath)**
+ http.external.service.auth `https://identity-service.example.com:443/authorize`

**OAuth Provider Config**
+ oauth.provider.name `Anypoint Bank`
+ oauth.token.ttl `36000`
+ oauth.scopes ` `
+ oauth.supported.grant.types `AUTHORIZATION_CODE,IMPLICIT`
+ oauth.authorization.endpoint.path `api/authorize`
+ oauth.access.token.endpoint.path `api/token`
+ oauth.enable.token.refresh `false`
+ login.page.path `html/login.html`
