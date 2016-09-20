#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "SecureStorage.h"
#import <Cordova/CDV.h>
#import "SSKeychain.h"

@implementation SecureStorage

@synthesize keychainAccesssibilityMapping;

NSString * const UIDevicePasscodeKeychainService = @"UIDevice-PasscodeStatus_KeychainService";
NSString * const UIDevicePasscodeKeychainAccount = @"UIDevice-PasscodeStatus_KeychainAccount";

- (void)get:(CDVInvokedUrlCommand*)command
{
    NSString *service = [command argumentAtIndex:0];
    NSString *key = [command argumentAtIndex:1];
    [self.commandDelegate runInBackground:^{
        NSError *error;

        SSKeychainQuery *query = [[SSKeychainQuery alloc] init];
        query.service = service;
        query.account = key;

        if ([query fetch:&error]) {
            [self successWithMessage: query.password : command.callbackId];
        } else {
            [self failWithMessage: @"Failure in SecureStorage.get()" : error : command.callbackId];
        }
    }];
}

- (void)set:(CDVInvokedUrlCommand*)command
{
    NSString *service = [command argumentAtIndex:0];
    NSString *key = [command argumentAtIndex:1];
    NSString *value = [command argumentAtIndex:2];
    [self.commandDelegate runInBackground:^{
        NSError *error;

        if (self.keychainAccesssibilityMapping == nil) {

            if( [[[UIDevice currentDevice] systemVersion] floatValue] >= 8.0 ){
                  self.keychainAccesssibilityMapping = [NSDictionary dictionaryWithObjectsAndKeys:
                                                      (__bridge id)(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly), @"afterfirstunlockthisdeviceonly",
                                                      (__bridge id)(kSecAttrAccessibleAfterFirstUnlock), @"afterfirstunlock",
                                                      (__bridge id)(kSecAttrAccessibleWhenUnlocked), @"whenunlocked",
                                                      (__bridge id)(kSecAttrAccessibleWhenUnlockedThisDeviceOnly), @"whenunlockedthisdeviceonly",
                                                      (__bridge id)(kSecAttrAccessibleAlways), @"always",
                                                      (__bridge id)(kSecAttrAccessibleAlwaysThisDeviceOnly), @"alwaysthisdeviceonly",
                                                      (__bridge id)(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly), @"whenpasscodesetthisdeviceonly",
                                                      nil];
            }
            else{
                  self.keychainAccesssibilityMapping = [NSDictionary dictionaryWithObjectsAndKeys:
                                                      (__bridge id)(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly), @"afterfirstunlockthisdeviceonly",
                                                      (__bridge id)(kSecAttrAccessibleAfterFirstUnlock), @"afterfirstunlock",
                                                      (__bridge id)(kSecAttrAccessibleWhenUnlocked), @"whenunlocked",
                                                      (__bridge id)(kSecAttrAccessibleWhenUnlockedThisDeviceOnly), @"whenunlockedthisdeviceonly",
                                                      (__bridge id)(kSecAttrAccessibleAlways), @"always",
                                                      (__bridge id)(kSecAttrAccessibleAlwaysThisDeviceOnly), @"alwaysthisdeviceonly",
                                                      nil];
            }
        }

        NSString* keychainAccessibility = [[self.commandDelegate.settings objectForKey:[@"KeychainAccessibility" lowercaseString]] lowercaseString];

        if ([self.keychainAccesssibilityMapping objectForKey:(keychainAccessibility)] != nil) {
            CFTypeRef accessibility = (__bridge CFTypeRef)([self.keychainAccesssibilityMapping objectForKey:(keychainAccessibility)]);
            [SSKeychain setAccessibilityType:accessibility];
        }

        SSKeychainQuery *query = [[SSKeychainQuery alloc] init];

        query.service = service;
        query.account = key;
        query.password = value;

        if ([query save:&error]) {
            [self successWithMessage: key : command.callbackId];
        } else {
            [self failWithMessage: @"Failure in SecureStorage.set()" : error : command.callbackId];
        }
    }];
}

- (void)remove:(CDVInvokedUrlCommand*)command
{
    NSString *service = [command argumentAtIndex:0];
    NSString *key = [command argumentAtIndex:1];
    [self.commandDelegate runInBackground:^{
        NSError *error;

        SSKeychainQuery *query = [[SSKeychainQuery alloc] init];
        query.service = service;
        query.account = key;

        if ([query deleteItem:&error]) {
            [self successWithMessage: key : command.callbackId];
        } else {
            [self failWithMessage: @"Failure in SecureStorage.get()" : error : command.callbackId];
        }
    }];
}

// FROM https://github.com/liamnichols/UIDevice-PasscodeStatus/blob/master/Source/UIDevice%2BPasscodeStatus.m
//  Created by Liam Nichols on 02/09/2014.
//  Copyright (c) 2014 Liam Nichols. All rights reserved.
/*
 The MIT License (MIT)
 
 Copyright (c) 2014 Liam Nichols
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
*/
- (void) isKeyguardSecure:(CDVInvokedUrlCommand*)command
{
    
#if TARGET_IPHONE_SIMULATOR
    NSLog(@"-[%@ %@] - not supported in simulator", NSStringFromClass([self class]), NSStringFromSelector(_cmd));
    [self successWithBoolean: NO : command.callbackId];
    return;
#endif
        
    static NSData *password = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        password = [NSKeyedArchiver archivedDataWithRootObject:NSStringFromSelector(_cmd)];
    });
    
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: UIDevicePasscodeKeychainService,
                            (__bridge id)kSecAttrAccount: UIDevicePasscodeKeychainAccount,
                            (__bridge id)kSecReturnData: @YES,
                            };
    
    CFErrorRef sacError = NULL;
    SecAccessControlRef sacObject;
    sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, kNilOptions, &sacError);
    
    // unable to create the access control item.
    if (sacObject == NULL || sacError != NULL) {
        
        [self successWithBoolean: NO : command.callbackId];
        return;
    }
    
    
    NSMutableDictionary *setQuery = [query mutableCopy];
    setQuery[(__bridge id) kSecValueData] = password;
    setQuery[(__bridge id) kSecAttrAccessControl] = (__bridge id) sacObject;
    
    OSStatus status;
    status = SecItemAdd((__bridge CFDictionaryRef)setQuery, NULL);
    
    // if we have the object, release it.
    if (sacObject) {
        CFRelease(sacObject);
        sacObject = NULL;
    }
    // if it failed to add the item.
    if (status == errSecDecode) {
        [self successWithBoolean: NO : command.callbackId];
        return;
    }
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
    
    // it managed to retrieve data successfully
    if (status == errSecSuccess) {
        [self successWithBoolean: YES : command.callbackId];
        return;
    }
    
    // not sure what happened, returning unknown
    [self successWithBoolean: NO : command.callbackId];
    return;
}

-(void)successWithBoolean:(BOOL)val : (NSString *)callbackId
{
    CDVPluginResult *commandResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:val];
    [self.commandDelegate sendPluginResult:commandResult callbackId:callbackId];
}

-(void)successWithMessage:(NSString *)message : (NSString *)callbackId
{
        CDVPluginResult *commandResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:message];
        [self.commandDelegate sendPluginResult:commandResult callbackId:callbackId];
}

-(void)failWithMessage:(NSString *)message : (NSError *)error : (NSString *)callbackId
{
    NSString        *errorMessage = (error) ? [NSString stringWithFormat:@"%@ - %@", message, [error localizedDescription]] : message;
    CDVPluginResult *commandResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errorMessage];

    [self.commandDelegate sendPluginResult:commandResult callbackId:callbackId];
}

@end
