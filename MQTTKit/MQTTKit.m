//
//  MQTTKit.m
//  MQTTKit
//
//  Created by Jeff Mesnil on 22/10/2013.
//  Copyright (c) 2013 Jeff Mesnil. All rights reserved.
//  Copyright 2012 Nicholas Humfrey. All rights reserved.
//

#import "MQTTKit.h"
#import "mosquitto.h"
#import <openssl/ssl.h>

#if 0 // set to 1 to enable logs

#define LogDebug(frmt, ...) NSLog(frmt, ##__VA_ARGS__);

#else

#define LogDebug(frmt, ...) {}

#endif

#pragma mark - MQTT Message

@interface MQTTMessage()

@property (readwrite, assign) unsigned short mid;
@property (readwrite, copy) NSString *topic;
@property (readwrite, copy) NSData *payload;
@property (readwrite, assign) MQTTQualityOfService qos;
@property (readwrite, assign) BOOL retained;

@end

@implementation MQTTMessage

-(id)initWithTopic:(NSString *)topic
           payload:(NSData *)payload
               qos:(MQTTQualityOfService)qos
            retain:(BOOL)retained
               mid:(short)mid
{
    if ((self = [super init])) {
        self.topic = topic;
        self.payload = payload;
        self.qos = qos;
        self.retained = retained;
        self.mid = mid;
    }
    return self;
}

- (NSString *)payloadString {
    return [[NSString alloc] initWithBytes:self.payload.bytes length:self.payload.length encoding:NSUTF8StringEncoding];
}

@end

#pragma mark - MQTT Client

@interface MQTTClient()

@property (nonatomic, copy) void (^connectionCompletionHandler)(NSUInteger code);
@property (nonatomic, strong) NSMutableDictionary *subscriptionHandlers;
@property (nonatomic, strong) NSMutableDictionary *unsubscriptionHandlers;
// dictionary of mid -> completion handlers for messages published with a QoS of 1 or 2
@property (nonatomic, strong) NSMutableDictionary *publishHandlers;
@property (nonatomic, assign) BOOL connected;

// dispatch queue to run the mosquitto_loop_forever.
@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, strong) NSMutableArray *certificateChain;

@end

@implementation MQTTClient



#pragma mark - mosquitto callback methods

static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
    MQTTClient* client = (__bridge MQTTClient*)obj;

    LogDebug(@"[%@] on_connect rc = %d", client.clientID, rc);
    client.connected = (rc == MQTTConnectionSuccess);
    if (client.connectionCompletionHandler) {
        client.connectionCompletionHandler(rc);
    }
}

static void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
    MQTTClient* client = (__bridge MQTTClient*)obj;
    LogDebug(@"[%@] on_disconnect rc = %d", client.clientID, rc);
    [client.publishHandlers removeAllObjects];
    [client.subscriptionHandlers removeAllObjects];
    [client.unsubscriptionHandlers removeAllObjects];

    client.connected = NO;
    if (client.disconnectionHandler) {
        client.disconnectionHandler(rc);
    }
}

static void on_publish(struct mosquitto *mosq, void *obj, int message_id)
{
    MQTTClient* client = (__bridge MQTTClient*)obj;
    NSNumber *mid = [NSNumber numberWithInt:message_id];
    void (^handler)(int) = [client.publishHandlers objectForKey:mid];
    if (handler) {
        handler(message_id);
        if (message_id > 0) {
            [client.publishHandlers removeObjectForKey:mid];
        }
    }
}

static void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *mosq_msg)
{
    // Ensure these objects are cleaned up quickly by an autorelease pool.
    // The GCD autorelease pool isn't guaranteed to clean this up in any amount of time.
    // Source: https://developer.apple.com/library/ios/DOCUMENTATION/General/Conceptual/ConcurrencyProgrammingGuide/OperationQueues/OperationQueues.html#//apple_ref/doc/uid/TP40008091-CH102-SW1
    @autoreleasepool {
        NSString *topic = [NSString stringWithUTF8String: mosq_msg->topic];
        NSData *payload = [NSData dataWithBytes:mosq_msg->payload length:mosq_msg->payloadlen];
        MQTTMessage *message = [[MQTTMessage alloc] initWithTopic:topic
                                                          payload:payload
                                                              qos:mosq_msg->qos
                                                           retain:mosq_msg->retain
                                                              mid:mosq_msg->mid];
        MQTTClient* client = (__bridge MQTTClient*)obj;
        LogDebug(@"[%@] on message %@", client.clientID, message);
        if (client.messageHandler) {
            client.messageHandler(message);
        }
    }
}

static void on_subscribe(struct mosquitto *mosq, void *obj, int message_id, int qos_count, const int *granted_qos)
{
    MQTTClient* client = (__bridge MQTTClient*)obj;
    NSNumber *mid = [NSNumber numberWithInt:message_id];
    MQTTSubscriptionCompletionHandler handler = [client.subscriptionHandlers objectForKey:mid];
    if (handler) {
        NSMutableArray *grantedQos = [NSMutableArray arrayWithCapacity:qos_count];
        for (int i = 0; i < qos_count; i++) {
            [grantedQos addObject:[NSNumber numberWithInt:granted_qos[i]]];
        }
        handler(grantedQos);
        [client.subscriptionHandlers removeObjectForKey:mid];
    }
}

static void on_unsubscribe(struct mosquitto *mosq, void *obj, int message_id)
{
    MQTTClient* client = (__bridge MQTTClient*)obj;
    NSNumber *mid = [NSNumber numberWithInt:message_id];
    void (^completionHandler)(void) = [client.unsubscriptionHandlers objectForKey:mid];
    if (completionHandler) {
        completionHandler();
        [client.subscriptionHandlers removeObjectForKey:mid];
    }
}

static bool on_verify_tls(struct mosquitto *mosq, void* obj, void *ctx, int open_ssl_preverify_ok) {
    MQTTClient* client = (__bridge MQTTClient*)obj;

    unsigned char *der_cert = NULL;

    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    int open_ssl_error = X509_STORE_CTX_get_error(ctx);
    int	depth = X509_STORE_CTX_get_error_depth(ctx);

    if (!cert) {
        LogDebug(@"Error getting X509 cert from mosq");
        return false;
    }

    int len = i2d_X509((X509 *)cert, &der_cert);

    if (!der_cert) {
        LogDebug(@"Error extracting DER from OpenSSL");
        return false;
    }

    if (!len) {
        LogDebug(@"Error extracting DER from OpenSSL");
        free(der_cert);
        return false;
    }

    NSData *certData = [NSData dataWithBytes:der_cert length:len];
    LogDebug(@"%@", certData);
    free(der_cert);

    SecCertificateRef certRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));

    if (!client.certificateChain) {
        [client setCertificateChain:[NSMutableArray new]];
    }

    [client.certificateChain addObject:(__bridge id)(certRef)];

    // only verify the hostname if the leaf certificate is available.
    SecPolicyRef policyRef = (depth == 0) ? SecPolicyCreateSSL(false, (__bridge CFStringRef)(client.host)) : SecPolicyCreateBasicX509();

    SecTrustRef trustRef = NULL;
    OSStatus status = SecTrustCreateWithCertificates(certRef, policyRef, &trustRef);

    SecTrustSetAnchorCertificates(trustRef, (__bridge CFArrayRef) client.certificateChain);
    SecTrustSetAnchorCertificatesOnly(trustRef, NO);

    if ((status != errSecSuccess) || !trustRef) {
        LogDebug(@"Error creating SecTrustRef: %@", @(status));

        CFRelease(certRef);
        CFRelease(policyRef);
        if (trustRef) {
            CFRelease(trustRef);
        }

        return false;
    }

    SecTrustResultType trustResult;
    status = SecTrustEvaluate(trustRef, &trustResult);

    //CFArrayRef debug = SecTrustCopyProperties(trustRef);

    bool validCert = false;
    LogDebug(@"SecTrustResult: %@", @(trustResult));

    if (open_ssl_error || status != 0) {
        LogDebug(@"OpenSSL error:num=%d:%s\n", open_ssl_error, X509_verify_cert_error_string(open_ssl_error));
        LogDebug(@"Status: %@", @(status));
    }

    if (((trustResult == kSecTrustResultProceed) || (trustResult == kSecTrustResultUnspecified))
        || (client.allowUntrustedCertificates &&
            ((trustResult == kSecTrustResultRecoverableTrustFailure) || (trustResult == kSecTrustResultUnspecified)))) {
        validCert = true;
    }
    
    CFRelease(certRef);
    CFRelease(policyRef);
    CFRelease(trustRef);

    return validCert;
}

// Initialize is called just before the first object is allocated
+ (void)initialize {
    mosquitto_lib_init();
}

+ (NSString*)version {
    int major, minor, revision;
    mosquitto_lib_version(&major, &minor, &revision);
    return [NSString stringWithFormat:@"%d.%d.%d", major, minor, revision];
}

- (MQTTClient*) initWithClientId: (NSString*) clientId
{
    return [self initWithClientId:clientId cleanSession:YES];
}

- (MQTTClient*) initWithClientId: (NSString *)clientId
                    cleanSession: (BOOL )cleanSession
{
    if ((self = [super init])) {
        self.clientID = clientId;
        self.port = 1883;
        self.keepAlive = 60;
        self.reconnectDelay = 1;
        self.reconnectDelayMax = 1;
        self.reconnectExponentialBackoff = NO;

        self.subscriptionHandlers = [[NSMutableDictionary alloc] init];
        self.unsubscriptionHandlers = [[NSMutableDictionary alloc] init];
        self.publishHandlers = [[NSMutableDictionary alloc] init];
        self.cleanSession = cleanSession;

        const char* cstrClientId = [self.clientID cStringUsingEncoding:NSUTF8StringEncoding];

        mosq = mosquitto_new(cstrClientId, self.cleanSession, (__bridge void *)(self));
        mosquitto_connect_callback_set(mosq, on_connect);
        mosquitto_disconnect_callback_set(mosq, on_disconnect);
        mosquitto_publish_callback_set(mosq, on_publish);
        mosquitto_message_callback_set(mosq, on_message);
        mosquitto_subscribe_callback_set(mosq, on_subscribe);
        mosquitto_unsubscribe_callback_set(mosq, on_unsubscribe);

        self.queue = dispatch_queue_create(cstrClientId, NULL);
    }
    return self;
}

- (void)setMessageRetry:(NSUInteger)seconds {
    mosquitto_message_retry_set(mosq, (unsigned int)seconds);
}

- (void)dealloc
{
    if (mosq) {
        mosquitto_destroy(mosq);
        mosq = NULL;
    }
}

#pragma mark - Connection

- (void)connectWithCompletionHandler:(void (^)(MQTTConnectionReturnCode code))completionHandler
{
    self.connectionCompletionHandler = completionHandler;

    const char *cstrHost = [self.host cStringUsingEncoding:NSASCIIStringEncoding];
    const char *cstrUsername = NULL, *cstrPassword = NULL;
    
    if (self.username)
        cstrUsername = [self.username cStringUsingEncoding:NSUTF8StringEncoding];
    
    if (self.password)
        cstrPassword = [self.password cStringUsingEncoding:NSUTF8StringEncoding];
    
    // FIXME: check for errors
    mosquitto_username_pw_set(mosq, cstrUsername, cstrPassword);
    mosquitto_reconnect_delay_set(mosq, self.reconnectDelay, self.reconnectDelayMax, self.reconnectExponentialBackoff);

    if (self.useTLS) {
        mosquitto_verify_ssl_callback_set(mosq, on_verify_tls);
    }

    dispatch_async(self.queue, ^{
        mosquitto_connect(mosq, cstrHost, self.port, self.keepAlive);

        LogDebug(@"start mosquitto loop on %@", self.queue);
        mosquitto_loop_forever(mosq, -1, 1);
        LogDebug(@"end mosquitto loop on %@", self.queue);
    });
}

- (void)connectToHost:(NSString *)host
    completionHandler:(void (^)(MQTTConnectionReturnCode code))completionHandler
{
    self.host = host;
    [self connectWithCompletionHandler:completionHandler];
}

- (void)reconnect {
    mosquitto_reconnect(mosq);
}

- (void)disconnectWithCompletionHandler:(MQTTDisconnectionHandler)completionHandler
{
    if (completionHandler) {
        self.disconnectionHandler = completionHandler;
    }
    mosquitto_disconnect(mosq);
}

- (void)setWillData:(NSData *)payload
            toTopic:(NSString *)willTopic
            withQos:(MQTTQualityOfService)willQos
             retain:(BOOL)retain
{
    const char* cstrTopic = [willTopic cStringUsingEncoding:NSUTF8StringEncoding];
    mosquitto_will_set(mosq, cstrTopic, (int)payload.length, payload.bytes, willQos, retain);
}

- (void)setWill:(NSString *)payload
        toTopic:(NSString *)willTopic
        withQos:(MQTTQualityOfService)willQos
         retain:(BOOL)retain;
{
    [self setWillData:[payload dataUsingEncoding:NSUTF8StringEncoding]
              toTopic:willTopic
              withQos:willQos
               retain:retain];
}

- (void)clearWill
{
    mosquitto_will_clear(mosq);
}

#pragma mark - Publish

- (void)publishData:(NSData *)payload
            toTopic:(NSString *)topic
            withQos:(MQTTQualityOfService)qos
             retain:(BOOL)retain
  completionHandler:(void (^)(int mid))completionHandler {
    const char* cstrTopic = [topic cStringUsingEncoding:NSUTF8StringEncoding];
    if (qos == 0 && completionHandler) {
        [self.publishHandlers setObject:completionHandler forKey:[NSNumber numberWithInt:0]];
    }
    int mid;
    mosquitto_publish(mosq, &mid, cstrTopic, (int)payload.length, payload.bytes, qos, retain);
    if (completionHandler) {
        if (qos == 0) {
            completionHandler(mid);
        } else {
            [self.publishHandlers setObject:completionHandler forKey:[NSNumber numberWithInt:mid]];
        }
    }
}

- (void)publishString:(NSString *)payload
              toTopic:(NSString *)topic
              withQos:(MQTTQualityOfService)qos
               retain:(BOOL)retain
    completionHandler:(void (^)(int mid))completionHandler; {
    [self publishData:[payload dataUsingEncoding:NSUTF8StringEncoding]
              toTopic:topic
              withQos:qos
               retain:retain
    completionHandler:completionHandler];
}

#pragma mark - Subscribe

- (void)subscribe: (NSString *)topic withCompletionHandler:(MQTTSubscriptionCompletionHandler)completionHandler {
    [self subscribe:topic withQos:0 completionHandler:completionHandler];
}

- (void)subscribe: (NSString *)topic withQos:(MQTTQualityOfService)qos completionHandler:(MQTTSubscriptionCompletionHandler)completionHandler
{
    const char* cstrTopic = [topic cStringUsingEncoding:NSUTF8StringEncoding];
    int mid;
    mosquitto_subscribe(mosq, &mid, cstrTopic, qos);
    if (completionHandler) {
        [self.subscriptionHandlers setObject:[completionHandler copy] forKey:[NSNumber numberWithInteger:mid]];
    }
}

- (void)unsubscribe: (NSString *)topic withCompletionHandler:(void (^)(void))completionHandler
{
    const char* cstrTopic = [topic cStringUsingEncoding:NSUTF8StringEncoding];
    int mid;
    mosquitto_unsubscribe(mosq, &mid, cstrTopic);
    if (completionHandler) {
        [self.unsubscriptionHandlers setObject:[completionHandler copy] forKey:[NSNumber numberWithInteger:mid]];
    }
}

@end
