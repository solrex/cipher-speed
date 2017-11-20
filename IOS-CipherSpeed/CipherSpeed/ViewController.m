//
//  ViewController.m
//  CipherSpeed
//
//  Created by Wenbo Yang on 2017/11/16.
//  Copyright © 2017年 Wenbo Yang. All rights reserved.
//

#import "ViewController.h"
#import <CommonCrypto/CommonCrypto.h>
#import "tea.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear: animated];
    [self runtest];
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (char *)random_bytes:(NSUInteger) len {
    char *buf = malloc(len);
    arc4random_buf(buf, len);
    return buf;
}


- (void)runtest {
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        const size_t PLAIN_DATA_SIZE = 10*1024*1024;
        char *aes_key_128 = [self random_bytes:kCCKeySizeAES128];
        char *des_key = [self random_bytes:kCCKeySizeDES];
        char *desede_key = [self random_bytes:kCCKeySize3DES];
        char *aes_iv = [self random_bytes:kCCBlockSizeAES128];
        char *des_iv = [self random_bytes:kCCBlockSizeDES];
        char *tea_key = [self random_bytes:16];
        
        char *plain = [self random_bytes:PLAIN_DATA_SIZE];
        char *cipher_data = malloc(PLAIN_DATA_SIZE + kCCBlockSizeAES128);
        char *dec_plain = malloc(PLAIN_DATA_SIZE + kCCBlockSizeAES128);
        
        size_t cipher_size = 0;
        size_t dec_plain_size = 0;
        NSDate *start;
        NSTimeInterval time_diff = 0;
        CCCryptorStatus status = 0;
        
        
        // AES CBC
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:@"# AES\n"];
        });
        start = [NSDate date];
        status = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCModeCBC | kCCOptionPKCS7Padding,
                         aes_key_128, kCCKeySizeAES128, aes_iv, plain, PLAIN_DATA_SIZE,
                         cipher_data, PLAIN_DATA_SIZE + kCCBlockSizeAES128, &cipher_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        //[_console insertText:[NSString stringWithFormat:@"cipher_size=%zu\n", cipher_size]];
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [AES/CBC/PKC7Padding] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        start = [NSDate date];
        status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCModeCBC | kCCOptionPKCS7Padding,
                         aes_key_128, kCCKeySizeAES128, aes_iv, cipher_data, cipher_size,
                         dec_plain, PLAIN_DATA_SIZE + kCCBlockSizeAES128, &dec_plain_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [AES/CBC/PKC7Padding] DEC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        start = [NSDate date];
        status = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCModeCBC,
                         aes_key_128, kCCKeySizeAES128, aes_iv, plain, PLAIN_DATA_SIZE,
                         cipher_data, PLAIN_DATA_SIZE + kCCBlockSizeAES128, &cipher_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            //[_console insertText:[NSString stringWithFormat:@"cipher_size=%zu\n", cipher_size]];
            [_console insertText:[NSString stringWithFormat:@"* [AES/CBC/NoPadding] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        start = [NSDate date];
        status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCModeCBC,
                         aes_key_128, kCCKeySizeAES128, aes_iv, cipher_data, cipher_size,
                         dec_plain, PLAIN_DATA_SIZE + kCCBlockSizeAES128, &dec_plain_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [AES/CBC/NoPadding] DEC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        // AES ECB
        start = [NSDate date];
        status = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCModeECB | kCCOptionPKCS7Padding,
                         aes_key_128, kCCKeySizeAES128, aes_iv, plain, PLAIN_DATA_SIZE,
                         cipher_data, PLAIN_DATA_SIZE + kCCBlockSizeAES128, &cipher_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [AES/ECB/PKC7Padding] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        start = [NSDate date];
        status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCModeECB | kCCOptionPKCS7Padding,
                         aes_key_128, kCCKeySizeAES128, aes_iv, cipher_data, cipher_size,
                         dec_plain, PLAIN_DATA_SIZE + kCCBlockSizeAES128, &dec_plain_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [AES/ECB/PKC7Padding] DEC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        start = [NSDate date];
        status = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCModeECB,
                         aes_key_128, kCCKeySizeAES128, aes_iv, plain, PLAIN_DATA_SIZE,
                         cipher_data, PLAIN_DATA_SIZE + kCCBlockSizeAES128, &cipher_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [AES/ECB/NoPadding] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        start = [NSDate date];
        status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCModeECB,
                         aes_key_128, kCCKeySizeAES128, aes_iv, cipher_data, cipher_size,
                         dec_plain, PLAIN_DATA_SIZE + kCCBlockSizeAES128, &dec_plain_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [AES/ECB/NoPadding] DEC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        // DES CBC
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:@"# DES\n"];
        });
        start = [NSDate date];
        status = CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCModeCBC | kCCOptionPKCS7Padding,
                         des_key, kCCKeySizeDES, des_iv, plain, PLAIN_DATA_SIZE,
                         cipher_data, PLAIN_DATA_SIZE + kCCBlockSizeDES, &cipher_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            //[_console insertText:[NSString stringWithFormat:@"cipher_size=%zu\n", cipher_size]];
            [_console insertText:[NSString stringWithFormat:@"* [DES/CBC/PKC7Padding] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        start = [NSDate date];
        status = CCCrypt(kCCDecrypt, kCCAlgorithmDES, kCCModeCBC | kCCOptionPKCS7Padding,
                         des_key, kCCKeySizeDES, des_iv, cipher_data, cipher_size,
                         dec_plain, PLAIN_DATA_SIZE + kCCBlockSizeDES, &dec_plain_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [DES/CBC/PKC7Padding] DEC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        start = [NSDate date];
        status = CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCModeCBC,
                         des_key, kCCKeySizeDES, des_iv, plain, PLAIN_DATA_SIZE,
                         cipher_data, PLAIN_DATA_SIZE + kCCBlockSizeDES, &cipher_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            //[_console insertText:[NSString stringWithFormat:@"cipher_size=%zu\n", cipher_size]];
            [_console insertText:[NSString stringWithFormat:@"* [DES/CBC/NoPadding] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        start = [NSDate date];
        status = CCCrypt(kCCDecrypt, kCCAlgorithmDES, kCCModeCBC,
                         des_key, kCCKeySizeDES, des_iv, cipher_data, cipher_size,
                         dec_plain, PLAIN_DATA_SIZE + kCCBlockSizeDES, &dec_plain_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [DES/CBC/NoPadding] DEC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        // DES ECB
        start = [NSDate date];
        status = CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCModeECB | kCCOptionPKCS7Padding,
                         des_key, kCCKeySizeDES, des_iv, plain, PLAIN_DATA_SIZE,
                         cipher_data, PLAIN_DATA_SIZE + kCCBlockSizeDES, &cipher_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            //[_console insertText:[NSString stringWithFormat:@"cipher_size=%zu\n", cipher_size]];
            [_console insertText:[NSString stringWithFormat:@"* [DES/ECB/PKC7Padding] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        start = [NSDate date];
        status = CCCrypt(kCCDecrypt, kCCAlgorithmDES, kCCModeECB | kCCOptionPKCS7Padding,
                         des_key, kCCKeySizeDES, des_iv, cipher_data, cipher_size,
                         dec_plain, PLAIN_DATA_SIZE + kCCBlockSizeDES, &dec_plain_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [DES/ECB/PKC7Padding] DEC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        start = [NSDate date];
        status = CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCModeECB,
                         des_key, kCCKeySizeDES, des_iv, plain, PLAIN_DATA_SIZE,
                         cipher_data, PLAIN_DATA_SIZE + kCCBlockSizeDES, &cipher_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            //[_console insertText:[NSString stringWithFormat:@"cipher_size=%zu\n", cipher_size]];
            [_console insertText:[NSString stringWithFormat:@"* [DES/ECB/NoPadding] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        start = [NSDate date];
        status = CCCrypt(kCCDecrypt, kCCAlgorithmDES, kCCModeECB,
                         des_key, kCCKeySizeDES, des_iv, cipher_data, cipher_size,
                         dec_plain, PLAIN_DATA_SIZE + kCCBlockSizeDES, &dec_plain_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [DES/ECB/NoPadding] DEC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        // 3DES CBC
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:@"# 3DES\n"];
        });
        start = [NSDate date];
        status = CCCrypt(kCCEncrypt, kCCAlgorithm3DES, kCCModeCBC | kCCOptionPKCS7Padding,
                         desede_key, kCCKeySize3DES, des_iv, plain, PLAIN_DATA_SIZE,
                         cipher_data, PLAIN_DATA_SIZE + kCCBlockSizeDES, &cipher_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            //[_console insertText:[NSString stringWithFormat:@"cipher_size=%zu\n", cipher_size]];
            [_console insertText:[NSString stringWithFormat:@"* [3DES/CBC/PKC7Padding] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        start = [NSDate date];
        status = CCCrypt(kCCDecrypt, kCCAlgorithm3DES, kCCModeCBC | kCCOptionPKCS7Padding,
                         desede_key, kCCKeySize3DES, des_iv, cipher_data, cipher_size,
                         dec_plain, PLAIN_DATA_SIZE + kCCBlockSizeDES, &dec_plain_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [3DES/CBC/PKC7Padding] DEC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        start = [NSDate date];
        status = CCCrypt(kCCEncrypt, kCCAlgorithm3DES, kCCModeCBC,
                         desede_key, kCCKeySize3DES, des_iv, plain, PLAIN_DATA_SIZE,
                         cipher_data, PLAIN_DATA_SIZE + kCCBlockSizeDES, &cipher_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            //[_console insertText:[NSString stringWithFormat:@"cipher_size=%zu\n", cipher_size]];
            [_console insertText:[NSString stringWithFormat:@"* [3DES/CBC/NoPadding] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        start = [NSDate date];
        status = CCCrypt(kCCDecrypt, kCCAlgorithm3DES, kCCModeCBC,
                         desede_key, kCCKeySize3DES, des_iv, cipher_data, cipher_size,
                         dec_plain, PLAIN_DATA_SIZE + kCCBlockSizeDES, &dec_plain_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [3DES/CBC/NoPadding] DEC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        // 3DES ECB
        start = [NSDate date];
        status = CCCrypt(kCCEncrypt, kCCAlgorithm3DES, kCCModeECB | kCCOptionPKCS7Padding,
                         desede_key, kCCKeySize3DES, des_iv, plain, PLAIN_DATA_SIZE,
                         cipher_data, PLAIN_DATA_SIZE + kCCBlockSizeDES, &cipher_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [3DES/ECB/PKC7Padding] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]]; });
        
        start = [NSDate date];
        status = CCCrypt(kCCDecrypt, kCCAlgorithm3DES, kCCModeECB | kCCOptionPKCS7Padding,
                         desede_key, kCCKeySize3DES, des_iv, cipher_data, cipher_size,
                         dec_plain, PLAIN_DATA_SIZE + kCCBlockSizeDES, &dec_plain_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [3DES/ECB/PKC7Padding] DEC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        start = [NSDate date];
        status = CCCrypt(kCCEncrypt, kCCAlgorithm3DES, kCCModeECB,
                         desede_key, kCCKeySize3DES, des_iv, plain, PLAIN_DATA_SIZE,
                         cipher_data, PLAIN_DATA_SIZE + kCCBlockSizeDES, &cipher_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            //[_console insertText:[NSString stringWithFormat:@"cipher_size=%zu\n", cipher_size]];
            [_console insertText:[NSString stringWithFormat:@"* [3DES/ECB/NoPadding] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        start = [NSDate date];
        status = CCCrypt(kCCDecrypt, kCCAlgorithm3DES, kCCModeECB,
                         desede_key, kCCKeySize3DES, des_iv, cipher_data, cipher_size,
                         dec_plain, PLAIN_DATA_SIZE + kCCBlockSizeDES, &dec_plain_size);
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(status == kCCSuccess, @"Crypt fail	");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [3DES/ECB/NoPadding] DEC: %.1f KB/ms\n", (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        
        // TEA
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:@"# TEA\n"];
        });
        memcpy(cipher_data, plain, PLAIN_DATA_SIZE);
        start = [NSDate date];
        for (size_t i=0; i<PLAIN_DATA_SIZE/8; i++) {
            tea_encrypt((uint32_t *)&cipher_data[i*8], (uint32_t *)tea_key);
        }
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        dispatch_async(dispatch_get_main_queue(), ^{
            //[_console insertText:[NSString stringWithFormat:@"cipher_size=%zu\n", cipher_size]];
            [_console insertText:[NSString stringWithFormat:@"* [TEA] ENC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });
        start = [NSDate date];
        for (size_t i=0; i<PLAIN_DATA_SIZE/8; i++) {
            tea_decrypt((uint32_t *)&cipher_data[i*8], (uint32_t *)tea_key);
        }
        time_diff = [[NSDate date] timeIntervalSinceDate:start];
        NSAssert(memcmp(cipher_data, plain, PLAIN_DATA_SIZE) == 0, @"Cipher error");
        dispatch_async(dispatch_get_main_queue(), ^{
            [_console insertText:[NSString stringWithFormat:@"* [TEA] DEC: %.1f KB/ms\n",
                                  (PLAIN_DATA_SIZE/1024.0)/(time_diff*1000)]];
        });

        free(aes_key_128);
        free(des_key);
        free(desede_key);
        free(aes_iv);
        free(des_iv);
        free(plain);
        free(cipher_data);
        free(dec_plain);
    });
}



@end
