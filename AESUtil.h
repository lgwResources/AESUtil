//
//  AESUtil.h
//  CarUtopia
//
//  Created by 刘功武 on 2021/4/20.
//

#import <Foundation/Foundation.h>

/**
 * AES工具类
 */
@interface AESUtil : NSObject
/**
 * AES加密
 * AESKey
 */
+ (NSString *)AESencrypt:(NSString *)sourceStr AESKey:(NSString *)AESKey;

/**
 * AES解密
 */
+ (NSString *)AESdecrypt:(NSString *)secretStr AESKey:(NSString *)AESKey;

@end
