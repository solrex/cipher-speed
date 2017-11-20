//
//  tea.h
//  CipherSpeed
//
//  Created by Wenbo Yang on 2017/11/20.
//  Copyright © 2017年 Wenbo Yang. All rights reserved.
//

#ifndef tea_h
#define tea_h

#include <stdint.h>

void tea_encrypt (uint32_t* v, uint32_t* k);

void tea_decrypt (uint32_t* v, uint32_t* k);


#endif /* tea_h */
