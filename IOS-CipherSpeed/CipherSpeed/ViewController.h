//
//  ViewController.h
//  CipherSpeed
//
//  Created by Wenbo Yang on 2017/11/16.
//  Copyright © 2017年 Wenbo Yang. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController

#pragma mark Console
@property (nonatomic,strong) IBOutlet UITextView *console;

- (char *)random_bytes:(NSUInteger) len;

- (void)runtest;

@end

