//
//  AESUtil.m
//  CarUtopia
//
//  Created by 刘功武 on 2021/4/20.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import "AESUtil.h"
 
@implementation AESUtil
 
+ (NSString *)AESencrypt:(NSString *)sourceStr AESKey:(NSString *)AESKey {

    if (sourceStr.length <= 0) return nil;
    if (!AESKey) {
        AESKey = @"abcdefghABCDEFGH";
    }
    char keyPtr[kCCKeySizeAES256 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [AESKey getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSData *data = [sourceStr dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;

    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding | kCCOptionECBMode, keyPtr, kCCKeySizeAES256, NULL, [data bytes], dataLength, buffer, bufferSize, &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        NSString *stringBase64 = [resultData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed]; // base64 格式的字符串
        return stringBase64;
    }
    free(buffer);
    return nil;
}

+ (NSString *)AESdecrypt:(NSString *)secretStr AESKey:(NSString *)AESKey {
    
    if (!secretStr.length) {
        return nil;
    }
    if (!AESKey.length) {
        AESKey = @"abcdefghABCDEFGH";
    }

    char keyPtr[kCCKeySizeAES256 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [AESKey getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:secretStr options:NSDataBase64DecodingIgnoreUnknownCharacters];//base64 解码
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding | kCCOptionECBMode, keyPtr, kCCKeySizeAES256, NULL, [data bytes], dataLength, buffer, bufferSize, &numBytesCrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    }
    free(buffer);
    return nil;
}

@end


