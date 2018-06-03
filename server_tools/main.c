/****************************************************************************************/
/*                          COPYRIGHT INFORMATION                                       */
/*    This program contains proprietary information which is a trade                    */
/*    secret of whaley Co., Ltd.and also is protected as an   unpublished               */
/*    work under applicable Copyright laws. Recipient is to retain this                 */
/*    program in confidence and is not permitted to use or make copies thereof          */
/*    other than as permitted in a written agreement written agreement with             */
/*    whaley Co., Ltd.                                                                  */
/*                                                                                      */
/*    All rights reserved. whaley Co., Ltd.                                             */
/****************************************************************************************/
/*
 ****************************************************************************************
 *
 *               main.c
 *
 * Filename      : main.c
 * Programmer(s) : system BSP
 * Filename      : main.c
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@whaley.cn
 * Create Time   : Thu 20 Aug 2015 03:02:41 AM EDT
 ****************************************************************************************
 */

#define MOUDLE_MAIN_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "cryptoType.h"
#include "cryptoAes.h"
#include "cryptoSha.h"
#include "cryptoRsa.h"
#include "cryptoDebug.h"
#include "cryptoPbkdf.h"



/*
 *******************************************************************************
 *                         FUNCTIONS SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          VARIABLES SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          FUNCTIONS USED ONLY BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          VARIABLES USED ONLY BY THIS MODULE
 *******************************************************************************
*/


CHAR g_handshakeOneData[] = 
{
    0x56, 0xf3, 0x26, 0x55, 0x60, 0x17, 0xce, 0x19, 0xab, 0xd4, 0xb9, 0x0b, 0x76, 0x53, 0x39, 0xdb, 
    0xa6, 0x02, 0x09, 0xf5, 0x80, 0xbb, 0x3a, 0xbe, 0x66, 0x2d, 0x1e, 0x3c, 0xe1, 0x91, 0x1a, 0x08, 
    0xa5, 0xf3, 0xc4, 0x43, 0x63, 0xa6, 0xb3, 0x8d, 0x1a, 0x51, 0x7e, 0x7a, 0xf3, 0x7f, 0x5d, 0xd9, 
    0x29, 0xdb, 0x39, 0xed, 0xce, 0xd9, 0x38, 0x1d, 0xd1, 0xbd, 0x94, 0x82, 0x4f, 0x5f, 0x79, 0xe3, 
    0x8a, 0x3f, 0xf9, 0x19, 0x72, 0x2a, 0x96, 0x82, 0x24, 0x64, 0xf7, 0x1b, 0x6c, 0xcb, 0x6e, 0x80, 
    0x90, 0x18, 0xca, 0x6e, 0x91, 0x8a, 0x96, 0xf5, 0x80, 0xde, 0x97, 0x13, 0x0b, 0x69, 0xbd, 0xe3, 
    0x74, 0x7e, 0xa3, 0xe7, 0x46, 0x7a, 0x1f, 0x2c, 0xa0, 0xa1, 0x8f, 0x72, 0x5e, 0x2a, 0x87, 0x81, 
    0x2f, 0xf2, 0xcd, 0x0d, 0x8c, 0xcb, 0x87, 0x4c, 0xec, 0x6e, 0x7d, 0x52, 0xa1, 0x73, 0xea, 0xa1, 
    0xbc, 0xcb, 0x68, 0x00, 0x06, 0xaa, 0x96, 0x58, 0x01, 0x26, 0x88, 0xa2, 0x5b, 0x23, 0xc3, 0xee, 
    0xf7, 0x52, 0xe2, 0x21, 0xff, 0x51, 0x2e, 0xee, 0x4d, 0xd4, 0x1f, 0xe7, 0xf4, 0x35, 0x32, 0x55, 
    0x8c, 0x44, 0xb2, 0x1b, 0x9a, 0x08, 0xce, 0x22, 0xb9, 0xaf, 0x26, 0x0c, 0xbe, 0x80, 0xac, 0xff, 
    0xa5, 0xd1, 0xc5, 0x0c, 0xfa, 0xdc, 0xed, 0x19, 0x99, 0x39, 0x46, 0x8b, 0x48, 0x18, 0x8b, 0xe7, 
    0xcd, 0xde, 0xd7, 0xb3, 0x12, 0xb3, 0x70, 0x52, 0xef, 0x62, 0xab, 0x76, 0x1f, 0x88, 0x10, 0x29, 
    0x5a, 0x90, 0x6a, 0x4d, 0xb5, 0x1b, 0x3e, 0x86, 0xdf, 0xfa, 0x0c, 0x9e, 0xf7, 0xb6, 0x49, 0xe1, 
    0xf6, 0xb0, 0x77, 0x9b, 0xea, 0x98, 0x3c, 0xaf, 0x13, 0x81, 0xb3, 0x7e, 0x08, 0xbb, 0x0a, 0xd7, 
    0x77, 0x94, 0x2a, 0x5f, 0x93, 0x40, 0x45, 0x72, 0xf4, 0x4f, 0xec, 0x83, 0x03, 0x83, 0xb7, 0xcd, 
    0x2d, 0x3b, 0xac, 0xac, 0xbd, 0xa7, 0xf5, 0x61, 0x60, 0xba, 0xf9, 0x8b, 0x7e, 0xb8, 0xcc, 0x2a, 
    0x61, 0x12, 0xb9, 0xc5, 0xfe, 0x89, 0xbb, 0x4e, 0xff, 0x0d, 0x63, 0x5b, 0xc5, 0x48, 0xeb, 0x67, 
    0x15, 0x04, 0xb1, 0x4c, 0x0f, 0xda, 0x14, 0x75, 0xf9, 0x1c, 0x92, 0x29, 0x6e, 0x2a, 0xb5, 0xa0, 
    0xb1, 0x39, 0x29, 0x91, 0xa3, 0xd1, 0xe1, 0xf9, 0x6d, 0x19, 0x92, 0xe8, 0xb1, 0x97, 0xb4, 0x9b, 
    0x74, 0x19, 0x7c, 0xf5, 0x72, 0x08, 0x0d, 0xc3, 0xb7, 0x91, 0xd8, 0xa8, 0xc3, 0xa8, 0xb1, 0x2f, 
    0x22, 0x98, 0xfb, 0xd9, 0xc2, 0x99, 0x47, 0x04, 0xa7, 0x19, 0x98, 0x55, 0xc6, 0x86, 0xfe, 0xf2, 
    0x9b, 0x4c, 0x4f, 0x13, 0xa0, 0x07, 0xb3, 0x54, 0xdc, 0x85, 0xf1, 0xfb, 0xc8, 0xb3, 0x41, 0x49, 
    0x13, 0x12, 0xee, 0x9a, 0x58, 0x80, 0x9c, 0xd5, 0xb0, 0xce, 0xd6, 0xff, 0x45, 0xd1, 0x97, 0x9e, 
    0x5f, 0x25, 0xbf, 0x08, 0x6a, 0x80, 0x50, 0x80, 0x44, 0x40, 0x70, 0x9f, 0x65, 0x7f, 0xf9, 0x4e, 
    0x3f, 0xc5, 0xfd, 0xc9, 0x90, 0x16, 0xdc, 0x6d, 0xca, 0xf1, 0xb5, 0x8c, 0x64, 0x26, 0x80, 0xf7, 
    0xcc, 0x4a, 0x57, 0x6e, 0x3c, 0x20, 0x77, 0xca, 0x81, 0xef, 0x88, 0x83, 0x26, 0x22, 0x20, 0x68, 
    0xbc, 0xae, 0x19, 0x25, 0x8d, 0x04, 0xaf, 0xb6, 0x9a, 0x9a, 0x73, 0x45, 0x89, 0xc8, 0xb0, 0x85, 
    0xab, 0xc8, 0x84, 0x9b, 0xb4, 0xd5, 0x34, 0xa8, 0x3d, 0xf8, 0x5c, 0x68, 0xbc, 0x4d, 0x6e, 0xfd, 
    0x9c, 0xc3, 0xcb, 0x5c, 0x89, 0x9d, 0x62, 0xa5, 0xaf, 0x73, 0x04, 0x2b, 0x72, 0x19, 0x23, 0x77, 
    0x1a, 0xc1, 0x22, 0xdc, 0xae, 0x39, 0x4c, 0x2b, 0xa3, 0x88, 0x93, 0xb0, 0x38, 0x1d, 0xde, 0x8f, 
    0x55, 0x83, 0x47, 0x4d, 0xcf, 0x3a, 0x14, 0x67, 0x2b, 0x0a, 0x09, 0x2f, 0xc9, 0xe7, 0x11, 0x53, 
    0x89, 0x63, 0x5d, 0xb0, 0x30, 0x34, 0x89, 0xe5, 0xec, 0x17, 0x94, 0xc2, 0xda, 0x33, 0x8c, 0xf9, 
    0xf7, 0xdc, 0x02, 0xcb, 0x53, 0xba, 0x04, 0xaa, 0x4f, 0x6c, 0x79, 0xf2, 0x81, 0xb5, 0x1f, 0x1e, 
    0x1f, 0xcd, 0x8c, 0x1b, 0xa5, 0x8a, 0x0c, 0xb5, 0x9b, 0x2b, 0x09, 0xed, 0x75, 0x9a, 0xb8, 0xc0, 
    0x32, 0xbd, 0xf7, 0xef, 0xcf, 0xa1, 0x2d, 0xc6, 0x4f, 0x7a, 0x03, 0xd8, 0x7f, 0xd8, 0xec, 0xb4, 
    0x8b, 0xf3, 0xaf, 0x3b, 0x64, 0x4c, 0x00, 0x47, 0xe6, 0xc4, 0xd0, 0x35, 0x7a, 0x2d, 0x0d, 0xaf, 
    0x1f, 0x0b, 0x92, 0xa5, 0x00, 0x79, 0xbe, 0x37, 0xd6, 0x52, 0xbf, 0x19, 0x7c, 0x0c, 0xb3, 0xc4, 
    0xd1, 0x91, 0x1f, 0x56, 0x81, 0x70, 0xdc, 0xc5, 0x63, 0x81, 0xe4, 0xeb, 0x5b, 0xa6, 0x92, 0x56, 
    0x15, 0x5e, 0x09, 0xae, 0xfe, 0x10, 0x57, 0x00, 0x86, 0xae, 0x03, 0x12, 0x87, 0x46, 0x3d, 0xbb, 
    0xb7, 0x5e, 0x1d, 0x50, 0xa0, 0x38, 0x2c, 0x5f, 0x35, 0xd8, 0x9c, 0x96, 0xb3, 0xf8, 0x0b, 0x93, 
    0xa4, 0x96, 0xf0, 0xd5, 0xf3, 0xef, 0xa5, 0xa1, 0x66, 0xb2, 0x8e, 0x2a, 0x78, 0x70, 0xb9, 0xe1, 
    0xa7, 0xc8, 0x8d, 0xb9, 0xf6, 0xf8, 0xca, 0x2e, 0xdf, 0x22, 0xd8, 0x77, 0x2c, 0xc0, 0xb0, 0x9e, 
    0xb1, 0xee, 0x12, 0x32, 0xfd, 0xe6, 0x00, 0xdf, 0xd8, 0xdb, 0x60, 0x90, 0xdc, 0x13, 0x02, 0x3d, 
    0x0f, 0x43, 0x0f, 0xb5, 0x3a, 0x7e, 0x4f, 0xbc, 0xf2, 0x48, 0x4c, 0xa2, 0x18, 0x76, 0xd7, 0x8b, 
    0x87, 0xc9, 0x14, 0x7a, 0xe3, 0x82, 0x98, 0x9f, 0x67, 0x45, 0x1e, 0x6b, 0xc5, 0x5f, 0xe3, 0x2f, 
    0x7e, 0xf1, 0x70, 0x6b, 0xd5, 0x07, 0xa4, 0x81, 0x58, 0xb6, 0xc1, 0x13, 0xbd, 0x75, 0x47, 0x5a, 
    0xa6, 0x67, 0xea, 0x43, 0xe8, 0x8a, 0xdd, 0xe3, 0x72, 0x1d, 0x2c, 0x3c, 0x48, 0xe2, 0xbb, 0x4c

};



CHAR g_Output2048[256] = {0};

CHAR g_HanshakeThreeData[] = 
{
    0x92, 0x72, 0xb9, 0x5a, 0xc4, 0xda, 0x1d, 0x50, 0x51, 0x39, 0x41, 0xb7, 0x2e, 0x2d, 0xfa, 0x43, 
    0xb7, 0x02, 0x31, 0x94, 0x15, 0x7a, 0x5b, 0x1d, 0xb1, 0xcd, 0x76, 0xa0, 0x2b, 0xd7, 0x38, 0x1a, 
    0xb5, 0xc3, 0xd5, 0x31, 0x3c, 0x1c, 0xcc, 0xdb, 0x11, 0xc3, 0xfb, 0x55, 0xee, 0xf0, 0x6c, 0x19, 
    0x16, 0x0e, 0x6b, 0xef, 0x24, 0x7e, 0xb7, 0xe2, 0xf5, 0xc8, 0x04, 0x9b, 0x36, 0x0a, 0xf3, 0x5a, 
    0x8b, 0x4b, 0xfb, 0xb7, 0x15, 0x34, 0x28, 0xdb, 0x6e, 0x33, 0xed, 0xbc, 0x9c, 0x99, 0xae, 0xc0, 
    0x72, 0xee, 0x94, 0x0b, 0x66, 0x96, 0xb2, 0xbf, 0x39, 0x48, 0x27, 0x19, 0x0c, 0x3c, 0x0a, 0x53, 
    0x37, 0xc5, 0x8b, 0xe3, 0x12, 0x0f, 0x9a, 0xb6, 0x1a, 0x85, 0x03, 0x15, 0xba, 0x28, 0x22, 0x42, 
    0x35, 0x14, 0x75, 0x8a, 0x82, 0xbd, 0xa7, 0x3f, 0x25, 0x49, 0x75, 0x90, 0x11, 0x82, 0xb1, 0xc0, 
    0xde, 0x71, 0x97, 0xc2, 0xe1, 0x30, 0x7e, 0xcc, 0xba, 0x2b, 0x88, 0x4c, 0xe4, 0xe8, 0x53, 0x42, 
    0xa5, 0x88, 0x95, 0xde, 0x0d, 0x99, 0x94, 0x79, 0x9c, 0xc1, 0x04, 0x7c, 0x3f, 0x9c, 0x3a, 0x8f, 
    0xf8, 0x55, 0xf8, 0x83, 0x57, 0x3f, 0xf7, 0xcf, 0xd1, 0x1b, 0x82, 0x4b, 0xac, 0x20, 0x5b, 0x61, 
    0xe3, 0x5a, 0xe5, 0x22, 0xb5, 0x02, 0xd2, 0x61, 0x27, 0xcc, 0x6e, 0x4e, 0x3a, 0xd4, 0xba, 0x9f, 
    0xe5, 0x65, 0x3b, 0xdb, 0x2e, 0xde, 0x81, 0xbf, 0x86, 0xcf, 0x4c, 0x80, 0x5e, 0xcc, 0xc9, 0x9c, 
    0xa0, 0x3e, 0xfa, 0x65, 0x80, 0x35, 0x4a, 0x53, 0xb6, 0xc0, 0xf9, 0x92, 0x2f, 0x78, 0xed, 0x9d, 
    0xf6, 0x4d, 0xd5, 0xf4, 0xa9, 0x61, 0x62, 0xeb, 0x40, 0xb1, 0x28, 0x13, 0x2a, 0x64, 0x29, 0x21, 
    0x90, 0x27, 0x7d, 0xc2, 0xfb, 0xa4, 0xca, 0x9a, 0x7b, 0x67, 0xed, 0xa4, 0x45, 0x27, 0x73, 0xb5, 
    0x71, 0xc7, 0xdb, 0x22, 0x73, 0x81, 0x98, 0xf1, 0x6f, 0xcd, 0x6b, 0x77, 0xeb, 0xcc, 0x93, 0x05, 
    0x64, 0x0a, 0xcf, 0xbe, 0x9b, 0x51, 0xc0, 0x9d, 0x00, 0xaa, 0xcc, 0x76, 0x06, 0x94, 0x9c, 0x97, 
    0x73, 0xa9, 0x74, 0xd2, 0x5a, 0xb3, 0x0e, 0x3d, 0xa3, 0x14, 0xbb, 0xef, 0x18, 0xbf, 0x74, 0xeb, 
    0x9e, 0x5f, 0x2d, 0x41, 0x30, 0xca, 0x13, 0x41, 0x29, 0xa2, 0xf4, 0xcd, 0xbd, 0xd3, 0xa1, 0x80, 
    0xb7, 0x78, 0x4e, 0x34, 0xb0, 0xc4, 0x5c, 0x93, 0x84, 0x8d, 0xcb, 0x67, 0x41, 0xe9, 0x18, 0x16, 
    0x21, 0x46, 0x5c, 0xdd, 0xce, 0x83, 0xd5, 0x5a, 0x87, 0x37, 0x94, 0x6d, 0xb1, 0x52, 0xbc, 0xd9, 
    0x69, 0x13, 0xac, 0x71, 0x3f, 0xae, 0x5a, 0x94, 0xa4, 0xc1, 0x92, 0x85, 0x8f, 0x9d, 0x0f, 0x6f, 
    0x94, 0xea, 0xc9, 0x18, 0xb9, 0x33, 0xb0, 0x2e, 0x6e, 0xd6, 0x66, 0x0d, 0xb9, 0x94, 0xfe, 0xff, 
    0x21, 0x95, 0x35, 0x70, 0xe8, 0x17, 0xdb, 0x6b, 0x4c, 0x48, 0x58, 0x1e, 0x23, 0xcb, 0xba, 0x09, 
    0xb4, 0x8a, 0xfc, 0xc2, 0x2f, 0xb4, 0x62, 0x1f, 0x72, 0xfb, 0x40, 0x6d, 0x2b, 0x08, 0x55, 0x14, 
    0xe8, 0xc1, 0xcc, 0x3b, 0x23, 0x4a, 0x73, 0x4c, 0xcf, 0xa9, 0x07, 0x30, 0x28, 0x17, 0x6a, 0x0a, 
    0x49, 0x09, 0x35, 0x25, 0x47, 0x8a, 0x5b, 0x5c, 0x57, 0x24, 0x80, 0x79, 0x51, 0x00, 0xf8, 0x6a, 
    0x0b, 0x6b, 0xa8, 0x28, 0x1d, 0xfd, 0x0b, 0xbf, 0xdd, 0x91, 0xf5, 0xe0, 0xe7, 0x45, 0xe3, 0xee, 
    0x90, 0xb4, 0xd2, 0x8d, 0x67, 0x88, 0xc8, 0x7a, 0xa7, 0x30, 0x7c, 0x59, 0x94, 0x2a, 0x3c, 0xc8, 
    0xfa, 0x4a, 0x8b, 0x61, 0x5a, 0x63, 0xcf, 0x3d, 0x03, 0xd1, 0xce, 0x4a, 0x92, 0xe4, 0x56, 0xc8, 
    0xfc, 0x6f, 0x10, 0x21, 0xf2, 0xe4, 0x93, 0xf2, 0x9f, 0x82, 0x70, 0xff, 0x95, 0x4f, 0xdf, 0xf7

};

CHAR g_PayData[] = 
{
 0x77, 0xe9, 0xad, 0x2c, 0xd5, 0x21, 0x18, 0x6b, 0xa1, 0x67, 0x45, 0xc7, 0x49, 0x23, 0x6f, 0x3f, 
0xb9, 0x88, 0x7a, 0x6a, 0x91, 0x61, 0xe3, 0xba, 0x93, 0x19, 0xfc, 0x7f, 0x62, 0xf3, 0x81, 0x64, 
0xbb, 0xea, 0xe6, 0x13, 0x7f, 0xd9, 0x1e, 0xee, 0x05, 0x9b, 0x9d, 0xe1, 0xc6, 0x24, 0x27, 0x06, 
0x5c, 0x43, 0xe1, 0x92, 0x91, 0x5e, 0x35, 0xcc, 0x64, 0x52, 0xff, 0xcc, 0x22, 0xa7, 0xd5, 0xc2, 
0x19, 0x42, 0x3a, 0xa4, 0x12, 0xce, 0x74, 0xda, 0x2b, 0x99, 0x98, 0x7b, 0x89, 0xf1, 0xfe, 0xf8, 
0xf1, 0xfe, 0x0c, 0xf6, 0x04, 0x6d, 0x95, 0x28, 0xa5, 0x1d, 0x64, 0x37, 0xdc, 0xfc, 0xbd, 0xbe, 
0x01, 0x88, 0x02, 0xe7, 0x0e, 0xf6, 0x6f, 0xe6, 0xe8, 0xcc, 0x43, 0xc5, 0x4d, 0x3a, 0x67, 0xbf, 
0xad, 0xd6, 0xbf, 0xae, 0x7f, 0x33, 0xd5, 0x71, 0xef, 0xcc, 0x96, 0x66, 0xae, 0x41, 0x5b, 0x21, 
0xd4, 0x83, 0xab, 0xbf, 0xc8, 0xae, 0x12, 0x2f, 0x0b, 0x63, 0x86, 0xb0, 0x31, 0xe8, 0x67, 0x76, 
0x1c, 0xea, 0x85, 0xf7, 0x40, 0x42, 0xdc, 0x5d, 0x3f, 0x4a, 0x7e, 0xd2, 0xa2, 0x2d, 0x33, 0xa6, 
0x39, 0x23, 0xa0, 0x28, 0x12, 0x39, 0xf0, 0xca, 0x6d, 0xd6, 0x08, 0xc9, 0x87, 0xb9, 0x80, 0x28, 
0x33, 0xcc, 0x21, 0x90, 0xec, 0x5a, 0x33, 0x11, 0x95, 0x9b, 0xca, 0x6e, 0x52, 0x3a, 0x02, 0x30, 
0x3e, 0xeb, 0x97, 0x5b, 0x66, 0x48, 0xf6, 0x13, 0x51, 0xa1, 0xad, 0x7d, 0x9b, 0x40, 0x55, 0xf4, 
0x72, 0x18, 0xa1, 0xfd, 0x2c, 0x08, 0x6b, 0x93, 0x4e, 0x84, 0x03, 0x3e, 0x49, 0x04, 0x7f, 0x65, 
0xb1, 0x21, 0xbb, 0x4c, 0x62, 0xf7, 0xda, 0xa4, 0x7a, 0xda, 0xb8, 0x99, 0xb2, 0xc0, 0x92, 0x46, 
0x36, 0xe0, 0x8d, 0x74, 0xb0, 0x73, 0xd2, 0xe5, 0x64, 0xea, 0xea, 0xc1, 0x71, 0x14, 0xdf, 0xe6, 
0x91, 0x90, 0x67, 0xac, 0x77, 0xb0, 0x1f, 0x55, 0x8b, 0xc1, 0xf4, 0x85, 0xb7, 0x2c, 0xdc, 0x5e, 
0x34, 0x63, 0xb1, 0xa7, 0xe0, 0x21, 0x0a, 0x86, 0xef, 0xab, 0x0b, 0xe3, 0x2e, 0x9c, 0xed, 0x2b, 
0x80, 0x59, 0x48, 0x98, 0xc8, 0xa5, 0x52, 0x93, 0x3d, 0x38, 0x33, 0x45, 0x5f, 0x81, 0x9c, 0x57, 
0x49, 0xe0, 0x6a, 0x14, 0x12, 0x71, 0xe9, 0x4c, 0x17, 0x9e, 0x90, 0x4a, 0xb8, 0xfe, 0x2a, 0xd3, 
0xae, 0x6b, 0x25, 0x35, 0x2e, 0xee, 0x4c, 0x0f, 0x2b, 0xff, 0xca, 0xaa, 0x19, 0x28, 0x68, 0xfb, 
0x4b, 0xac, 0xf8, 0x47, 0x93, 0xc1, 0xc9, 0xdf, 0x0c, 0x2d, 0x33, 0x04, 0xe6, 0xfd, 0x94, 0x32, 
0x04, 0xdc, 0x1c, 0x1c, 0x61, 0x9e, 0xf9, 0xb2, 0x68, 0xdd, 0x25, 0xed, 0x46, 0x3e, 0x53, 0xae, 
0x4b, 0xd2, 0x99, 0x36, 0x33, 0x6c, 0x42, 0x29, 0x46, 0x9b, 0x0a, 0x00, 0x7c, 0x9d, 0x51, 0xe7, 
0x46, 0x1e, 0xa1, 0x54, 0x3d, 0x68, 0xe4, 0x6f, 0xf7, 0x9a, 0x03, 0x44, 0xa7, 0xf9, 0x73, 0x0d, 
0xde, 0x63, 0xe9, 0xe7, 0x88, 0x87, 0x7a, 0x29, 0x37, 0x4d, 0x71, 0x3c, 0x72, 0x1f, 0x48, 0x92, 
0x5c, 0xc3, 0x58, 0xae, 0xef, 0xf4, 0x49, 0x1f, 0x95, 0x62, 0x57, 0x1c, 0x7d, 0x95, 0x2e, 0x0d, 
0x8d, 0x29, 0x4f, 0x49, 0x1d, 0x28, 0x0b, 0x8e, 0x12, 0xbb, 0xff, 0x86, 0x14, 0x8e, 0x78, 0x0e, 
0x8f, 0xd5, 0x9b, 0x35, 0x81, 0xb4, 0x4b, 0x1c, 0xb2, 0xe7, 0xa6, 0x6f, 0xc7, 0xa2, 0xf1, 0x32, 
0x32, 0xbf, 0xf7, 0x31, 0xed, 0x3b, 0xc8, 0x99, 0xe8, 0x4f, 0x52, 0x96, 0xb4, 0xba, 0x83, 0x48, 
0x3b, 0x39, 0x01, 0x6e, 0x5a, 0xe9, 0x62, 0xb7, 0x9d, 0x54, 0x80, 0x82, 0xb1, 0xec, 0x04, 0xab, 
0x62, 0x82, 0x0e, 0x80, 0xcd, 0x19, 0xcc, 0x5e, 0xd5, 0x09, 0x4e, 0x8d, 0x9a, 0x05, 0xb2, 0x00
};



CHAR g_PayOverData[512] = {0};


CHAR g_DefHandShakeOne[] = "!Data for handshake one!";
CHAR g_DefHandShakeTwo[] = "@Data for handshake two@";
CHAR g_DefHandShakeThree[] = "Data for handshake three";
CHAR g_DefPayReq[] = "###Requestion of on line pay operation##";
CHAR g_PayOperComplete[] = "&&On line pay execute completely";


CHAR g_RandomOne[16] = 
{
    0x11, 0x02, 0x0a, 0x0f, 0x05, 0x43, 0x74, 0x9a,
    0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x22, 0x44, 0x07
};
CHAR g_RandomTwo[16] = 
{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11
};
CHAR g_RandomThree[16] = 
{
    0x11, 0x02, 0x0a, 0x0f, 0x05, 0x43, 0x74, 0x9a,
    0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x22, 0x44, 0x07
};


CHAR g_HandshakeTwoData[512] = {0};
CHAR g_EncHSTwo[512] = {0};
OnLinePayData g_OnLinePayData;

CHAR temrandom[16] = 
{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11
};

/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/

CHAR temp[] = 
{
    0x1f, 0xf1, 0xf7, 0x34, 0xb5, 0x02, 0x47, 0x30, 0x77, 0xbc, 0x91, 0x37, 0x76, 0x3c, 0xfa, 0xc9, 
    0x7f, 0xc2, 0xf1, 0x50, 0x8e, 0x81, 0x12, 0x0f, 0xd4, 0x32, 0x4b, 0x4b, 0xd4, 0x8e, 0xf6, 0xd9, 
    0x81, 0x82, 0xe3, 0x08, 0x97, 0x6c, 0xe5, 0x3c, 0x81, 0xc4, 0xfd, 0x37, 0x47, 0x08, 0x7b, 0x68, 
    0x63, 0x5a, 0xb9, 0x97, 0x2a, 0x0f, 0x79, 0xfb, 0xee, 0xc6, 0xe8, 0x05, 0x04, 0xd7, 0x4d, 0x2d, 
    0xa6, 0x0c, 0x0e, 0xb5, 0x64, 0x6f, 0x6b, 0x1b, 0xdd, 0xaf, 0xcf, 0xa7, 0x92, 0x3a, 0xf5, 0xb6, 
    0x30, 0x10, 0x1d, 0xfb, 0xcf, 0x7a, 0x15, 0x7a, 0x15, 0x57, 0x43, 0x95, 0x18, 0x28, 0x76, 0x14, 
    0xaa, 0xd2, 0x18, 0x4f, 0xe2, 0x5f, 0xaf, 0x39, 0xea, 0x7c, 0xaf, 0x74, 0x8a, 0xe7, 0xe0, 0x1a, 
    0xe4, 0x60, 0x03, 0x93, 0xca, 0x6e, 0xa0, 0x77, 0xbc, 0x28, 0x87, 0x46, 0x4a, 0xc0, 0x1d, 0x87, 
    0xd9, 0x76, 0xc7, 0x90, 0x15, 0x3a, 0x08, 0x27, 0x5d, 0xe3, 0x75, 0x7a, 0x7b, 0xcb, 0xb5, 0x23, 
    0xc9, 0x6c, 0xc2, 0xba, 0x62, 0x33, 0x78, 0x48, 0xf0, 0x7e, 0x73, 0x1e, 0x0e, 0x7a, 0xbe, 0x11, 
    0x54, 0x8f, 0x1c, 0x86, 0xb0, 0x2f, 0x08, 0x2b, 0x08, 0x57, 0x57, 0x0d, 0x91, 0x32, 0xb4, 0x7c, 
    0x67, 0x4d, 0xd5, 0x10, 0xa5, 0x36, 0xb9, 0x7a, 0x74, 0x73, 0x75, 0x55, 0xf9, 0xfb, 0xe4, 0x0c, 
    0x99, 0x7c, 0x89, 0x3f, 0x3b, 0x18, 0xa5, 0xeb, 0x11, 0x77, 0x9e, 0xe0, 0xb0, 0xc1, 0x88, 0xf2, 
    0xc2, 0xbc, 0xe7, 0xb3, 0xa8, 0xfc, 0x04, 0x5f, 0x8d, 0xf5, 0x8e, 0xee, 0x21, 0x83, 0x06, 0x6b, 
    0xd7, 0x2f, 0x7c, 0x73, 0xe3, 0xec, 0xc3, 0xb1, 0x0c, 0x6a, 0xa1, 0x2e, 0x26, 0xda, 0x5d, 0x37, 
    0xc6, 0xc7, 0x9e, 0xa6, 0x00, 0x17, 0xcc, 0xd0, 0x6e, 0x52, 0xdc, 0x61, 0x78, 0x0e, 0x2b, 0x3b, 
    0x9f, 0x2e, 0xcb, 0xab, 0x6d, 0x3e, 0xf4, 0x5b, 0xb2, 0xe0, 0x5e, 0x1d, 0xdf, 0x5a, 0x12, 0x38, 
    0x05, 0xbd, 0x04, 0xe2, 0x33, 0x57, 0x41, 0xbc, 0xc0, 0x8f, 0xb3, 0xcc, 0x73, 0x03, 0xec, 0xe7, 
    0xb2, 0x47, 0xa2, 0x1b, 0xed, 0x12, 0xf0, 0xd2, 0x17, 0x9c, 0xd0, 0x16, 0x0f, 0x4a, 0x85, 0xa3, 
    0x1b, 0xae, 0x8f, 0x22, 0x44, 0xbb, 0xbb, 0x9f, 0x5d, 0x73, 0x98, 0x94, 0x6c, 0xc6, 0x71, 0xa1, 
    0x18, 0xbd, 0xfe, 0x27, 0x4d, 0xb9, 0xb7, 0xf1, 0xeb, 0xc2, 0x13, 0x53, 0x7f, 0xd1, 0x3e, 0x98, 
    0x0c, 0xa2, 0xa5, 0xd5, 0x36, 0x0a, 0xe9, 0x44, 0x64, 0x79, 0x6a, 0xed, 0xb9, 0x9e, 0x9c, 0x31, 
    0x87, 0xc5, 0x9a, 0x01, 0xac, 0x01, 0x46, 0x36, 0xb4, 0x2e, 0xb7, 0x29, 0x87, 0x51, 0xb4, 0x36, 
    0xfa, 0xd3, 0x85, 0x73, 0xaa, 0xe0, 0x03, 0x86, 0x21, 0x9e, 0x7f, 0x64, 0x7d, 0x43, 0x4b, 0x37, 
    0x9a, 0x14, 0x70, 0x12, 0x2a, 0x7f, 0xe0, 0x5a, 0x52, 0xce, 0x7a, 0x63, 0xf2, 0x6e, 0x49, 0x46, 
    0x38, 0x0c, 0x5f, 0x8a, 0x74, 0xd6, 0xaf, 0x81, 0xc1, 0x3a, 0x0e, 0x3b, 0x9b, 0x63, 0x2a, 0x08, 
    0x38, 0xb4, 0xbf, 0xf9, 0x55, 0x98, 0x4f, 0xf2, 0x25, 0x3a, 0x2e, 0xe6, 0x3f, 0xc0, 0x37, 0xf1, 
    0x29, 0xbb, 0x63, 0x82, 0xaa, 0x09, 0xe0, 0xb9, 0xc6, 0x94, 0x7a, 0x81, 0x19, 0x1b, 0x5c, 0x9e, 
    0x28, 0xc4, 0x0c, 0x20, 0xb3, 0x6a, 0x55, 0x54, 0xff, 0x27, 0x63, 0xef, 0x70, 0x06, 0xd1, 0x7f, 
    0x47, 0xd1, 0x03, 0x4f, 0x99, 0xa4, 0x6e, 0xbb, 0xce, 0xb8, 0x66, 0xe4, 0x67, 0x8a, 0xe1, 0x78, 
    0xe7, 0xa3, 0xbd, 0xbd, 0x00, 0x69, 0x71, 0x92, 0x09, 0xb8, 0x3a, 0x50, 0xdc, 0x2a, 0xd5, 0x76, 
    0x8f, 0x29, 0x63, 0xb2, 0x39, 0x66, 0xac, 0x29, 0xa8, 0xcc, 0x64, 0x24, 0xe2, 0x3f, 0x37, 0x86

};

int l_OnLinePayTaHandle_CheckHandshakeOne(UINT32 inLen, CHAR* pInput)
{
    UINT16 l_Purpose = 0x0U;
    CHAR* l_DataSection = NULL;
    UINT32 l_dataLen = 0U;
    UINT32 l_RandomLen = 0U;
    CHAR* l_pRandom = NULL;
    int l_Ret = -1;
    UINT32 g_lenOfDataSection = 0U;
    CHAR g_KeyAlgorithm = 0x00;
    
    /** 1) Check version of protocol */
    if(PROTOCOL_VERSION != pInput[0])
    {
        TF("PROTOCOL VERSION don't match\n");
        return -1;
    }
    
    /** 2) Check version of protocol */
    if(ALGORITHM_VERSION != pInput[1])
    {
        TF("ALGORITHM VERSION don't match\n");
        return -1;
    }
    
    /** 3) Get key number of algorithm */
    g_KeyAlgorithm = pInput[4];

    /** 4) Check purpose of package */
    l_Purpose = (pInput[9]) & 0xFFU;
    l_Purpose = (l_Purpose << 8) | pInput[8];
    if(PURPOSE_FOR_HANDSHAKE_ONE != l_Purpose)
    {
        TF("Purpose don't match\n");
        return -1;
    }

    /** 5) Get length of data section */
    g_lenOfDataSection = (pInput[13]) & 0xFFU;
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[12];
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[11];
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[10];
    l_DataSection = &(pInput[14]);

    /** 6) Get data length */
    l_dataLen = (l_DataSection[3]) & 0xFFU;
    l_dataLen = (l_dataLen << 8) | l_DataSection[2];
    l_dataLen = (l_dataLen << 8) | l_DataSection[1];
    l_dataLen = (l_dataLen << 8) | l_DataSection[0];
    TF("Data length is: 0x%04x\n", l_dataLen);

    /** 7) Compare data */
    TF("Input data just like below:\n");
    //g_TA_Printf(&(l_DataSection[4]), l_dataLen);
    l_Ret = memcmp(g_DefHandShakeTwo, &(l_DataSection[4]), l_dataLen);
    if(-1 == l_Ret)
    {
        return -1;
    }

    /** 6) Random */
    l_pRandom = &(l_DataSection[l_dataLen + 4]);
    l_RandomLen = (l_pRandom[3]) & 0xFFU;
    l_RandomLen = (l_RandomLen << 8) | l_pRandom[2];
    l_RandomLen = (l_RandomLen << 8) | l_pRandom[1];
    l_RandomLen = (l_RandomLen << 8) | l_pRandom[0];
    memcpy(g_RandomTwo, &(l_pRandom[4]), l_RandomLen);
    TF("second random is:%d\n", l_RandomLen);
    g_Debug_Printf(g_RandomTwo, l_RandomLen);

    return 0;
}

int l_OnLinePayTaHandle_CheckHandshakeThree(UINT32 inLen, CHAR* pInput)
{
    UINT16 l_Purpose = 0x0U;
    CHAR* l_DataSection = NULL;
    UINT32 l_dataLen = 0U;
    UINT32 l_RandomLen = 0U;
    CHAR* l_pRandom = NULL;
    int l_Ret = -1;
    UINT32 g_lenOfDataSection = 0U;
    CHAR g_KeyAlgorithm = 0x00;
    
    /** 1) Check version of protocol */
    if(PROTOCOL_VERSION != pInput[0])
    {
        TF("PROTOCOL VERSION don't match\n");
        return -1;
    }
    
    /** 2) Check version of protocol */
    if(ALGORITHM_VERSION != pInput[1])
    {
        TF("ALGORITHM VERSION don't match\n");
        return -1;
    }
    
    /** 3) Get key number of algorithm */
    g_KeyAlgorithm = pInput[4];

    /** 4) Check purpose of package */
    l_Purpose = (pInput[9]) & 0xFFU;
    l_Purpose = (l_Purpose << 8) | pInput[8];
    if(PURPOSE_FOR_HANDSHAKE_THREE != l_Purpose)
    {
        TF("Purpose don't match\n");
        return -1;
    }

    /** 5) Get length of data section */
    g_lenOfDataSection = (pInput[13]) & 0xFFU;
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[12];
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[11];
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[10];
    l_DataSection = &(pInput[14]);

    /** 6) Get data length */
    l_dataLen = (l_DataSection[3]) & 0xFFU;
    l_dataLen = (l_dataLen << 8) | l_DataSection[2];
    l_dataLen = (l_dataLen << 8) | l_DataSection[1];
    l_dataLen = (l_dataLen << 8) | l_DataSection[0];
    TF("Data length is: 0x%04x\n", l_dataLen);

    /** 7) Compare data */
    TF("Input data just like below:\n");
    //g_TA_Printf(&(l_DataSection[4]), l_dataLen);
    l_Ret = memcmp(g_DefHandShakeThree, &(l_DataSection[4]), l_dataLen);
    if(-1 == l_Ret)
    {
        return -1;
    }

    /** 6) Random */
    l_pRandom = &(l_DataSection[l_dataLen + 4]);
    l_RandomLen = (l_pRandom[3]) & 0xFFU;
    l_RandomLen = (l_RandomLen << 8) | l_pRandom[2];
    l_RandomLen = (l_RandomLen << 8) | l_pRandom[1];
    l_RandomLen = (l_RandomLen << 8) | l_pRandom[0];
    memcpy(g_RandomThree, &(l_pRandom[4]), l_RandomLen);
    TF("second random is:%d\n", l_RandomLen);
    g_Debug_Printf(g_RandomThree, l_RandomLen);

    return 0;
}


int l_OnLinePayTaHandle_CheckPaydata(UINT32 inLen, CHAR* pInput)
{
    UINT16 l_Purpose = 0x0U;
    CHAR* l_DataSection = NULL;
    UINT32 l_dataLen = 0U;
    UINT32 l_RandomLen = 0U;
    CHAR* l_pRandom = NULL;
    int l_Ret = -1;
    UINT32 g_lenOfDataSection = 0U;
    CHAR g_KeyAlgorithm = 0x00;
    /** 1) Check version of protocol */
    if(PROTOCOL_VERSION != pInput[0])
    {
        TF("PROTOCOL VERSION don't match\n");
        return -1;
    }

    /** 2) Check version of protocol */
    if(ALGORITHM_VERSION != pInput[1])
    {
        TF("ALGORITHM VERSION don't match\n");
        return -1;
    }
    
    /** 3) Get key number of algorithm */
    g_KeyAlgorithm = pInput[4];

    /** 4) Check purpose of package */
    l_Purpose = (pInput[9]) & 0xFFU;
    l_Purpose = (l_Purpose << 8) | pInput[8];
    if(PURPOSE_FOR_PAYING_OPERATION != l_Purpose)
    {
        TF("Purpose don't match\n");
        return -1;
    }

    /** 5) Get length of data section */
    g_lenOfDataSection = (pInput[13]) & 0xFFU;
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[12];
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[11];
    g_lenOfDataSection = (g_lenOfDataSection << 8) | pInput[10];
    l_DataSection = &(pInput[14]);


    /** 6) Get data length */
    l_dataLen = (l_DataSection[3]) & 0xFFU;
    l_dataLen = (l_dataLen << 8) | l_DataSection[2];
    l_dataLen = (l_dataLen << 8) | l_DataSection[1];
    l_dataLen = (l_dataLen << 8) | l_DataSection[0];
    TF("Data length is: 0x%04x\n", l_dataLen);

    /** 7) Compare data */
    TF("Input data just like below:\n");
    g_Debug_Printf(&(l_DataSection[4]), l_dataLen);
    l_Ret = memcmp(g_DefHandShakeThree, &(l_DataSection[4]), l_dataLen);
    if(-1 == l_Ret)
    {
        return -1;
    }
    else
    {
        TF("Compare OK\n");
    }


    return 0;
}



void l_handshakeone_analy(CHAR* output, UINT32 outputLen, CHAR* keyFile)
{
    char hash[20] = {0};

    g_CryptoRsa_Decrypt(keyFile, g_handshakeOneData, sizeof(g_handshakeOneData), output, RSA_NO_PADDING);
    printf("RSA dec-nopad output just like follow:\n");
    g_Debug_Printf(output, 768);
    l_OnLinePayTaHandle_CheckHandshakeOne(256, output);
}


void l_handshakethree_analy(CHAR* output, UINT32 outputLen, CHAR* keyFile1, CHAR* keyFile2)
{
    char hash[20] = {0};


    g_CryptoRsa_Verify(keyFile1, g_HanshakeThreeData, 256, &(g_HanshakeThreeData[256]), RSA_PKCS1_PADDING);
    
    g_CryptoRsa_Decrypt(keyFile2, g_HanshakeThreeData, 256, output, RSA_NO_PADDING);
    printf("RSA dec-nopad output just like follow:\n");
    g_Debug_Printf(output, 256);
    l_OnLinePayTaHandle_CheckHandshakeThree(256, output);

    g_CryptoAes_SetKey(g_RandomOne, g_RandomTwo, g_RandomThree);
}


UINT32 l_OnLinePayTaHandle_PackageHandshakeTwo(CHAR* pBuf, UINT32  len)
{
    UINT32 l_Ret = 0U;
    HandshakeData l_HandData;

    /** 1) Clean buffer */
    memset(&g_OnLinePayData, 0, sizeof(OnLinePayData) - 256);
    RAND_bytes(pBuf, len);

    /** 2) Assemble data of data section */
    l_HandData.mDataOne = g_DefHandShakeTwo;
    l_HandData.mLenOne = sizeof(g_DefHandShakeTwo) - 1;

    /** 3) Get first random */
    //RAND_bytes(g_RandomTwo, 16);
    //memcpy(g_RandomTwo, temrandom, 16);
    TF("The out put length is\n");
    g_Debug_Printf(g_RandomTwo, 16);
    l_HandData.mRandom = g_RandomTwo;
    l_HandData.mLenRandom = 16U;

    /** 2) Package plaintext */
    /** 2.1) Package header section */
    g_OnLinePayData.mHeaderSection.mVersion[0] = PROTOCOL_VERSION;  //Version of data
    g_OnLinePayData.mHeaderSection.mVersion[1] = ALGORITHM_VERSION;  // use RSA2048-SHA1-PKCS1 to sign data
    g_OnLinePayData.mHeaderSection.mFrom = DATA_FROM_SERVICE;    // Data from Client
    g_OnLinePayData.mHeaderSection.mTo = DATA_TO_CLIENT;      // Data to service
    g_OnLinePayData.mHeaderSection.mNum = FLAG_HANDSHAKE_KEY;

    /** 2.2) Package data section */
    g_OnLinePayData.mDataSection.mPurpose = PURPOSE_FOR_HANDSHAKE_TWO;
    g_OnLinePayData.mDataSection.mLength = l_HandData.mLenOne + l_HandData.mLenRandom + 8U;
    g_OnLinePayData.mDataSection.mPdata = (CHAR*)(&l_HandData);
  
    /** 3) Copy plain data into buffer */
    l_Ret = sizeof(OnLinePayHeaderSection);    //Length of header + mPurpose + mLength
    memcpy(pBuf, &g_OnLinePayData, l_Ret);

    /** 4) Put length and data content into bufffer */
    memcpy(&(pBuf[l_Ret]), &(g_OnLinePayData.mDataSection.mPurpose), sizeof(UINT16));
    l_Ret = l_Ret + sizeof(UINT16);

    memcpy(&(pBuf[l_Ret]), &(g_OnLinePayData.mDataSection.mLength), sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);
    
    memcpy(&(pBuf[l_Ret]), &(l_HandData.mLenOne), sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);
    memcpy(&(pBuf[l_Ret]), g_DefHandShakeTwo, sizeof(g_DefHandShakeTwo));
    l_Ret = l_Ret + sizeof(g_DefHandShakeTwo) - 1;

    /** 5) Put length and random data into buffer */
    memcpy(&(pBuf[l_Ret]), &(l_HandData.mLenRandom), sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);
    memcpy(&(pBuf[l_Ret]), g_RandomTwo, 16);
    l_Ret = l_Ret + 16;
    
    /** 7) Return length of plain text data */
    return l_Ret;
}



int l_paydata_analy(CHAR* buf, UINT32 bufLen, CHAR* key)
{
    char hash[20] = {0};
    CHAR l_PlainText[256] = {0};
    
    g_CryptoRsa_Verify(key, buf, 256, &(buf[256]), RSA_PKCS1_PADDING);

    TF("Entry AES Decrypt!\n");
    g_CryptoAes_decrypt(buf, 256U, EN_MODE_CBC, l_PlainText);
    TF("Dec over, output just like below:\n");
    g_Debug_Printf(l_PlainText, 256U);
    l_OnLinePayTaHandle_CheckPaydata(256, l_PlainText);

    return 0;
}



UINT32 l_OnLinePayTaHandle_PackagePayOver(CHAR* pBuf, UINT32  len)
{
    UINT32 l_Ret = 0U;
    PayData l_PayoverData;

    /** 1) Clean buffer */
    memset(&g_OnLinePayData, 0, sizeof(OnLinePayData) - 256);
    RAND_bytes(pBuf, len);

    /** 2) Assemble data of data section */
    l_PayoverData.mPayData = g_PayOperComplete;
    l_PayoverData.mPayDataLen = sizeof(g_PayOperComplete) - 1;


    /** 2) Package plaintext */
    /** 2.1) Package header section */
    g_OnLinePayData.mHeaderSection.mVersion[0] = PROTOCOL_VERSION;  //Version of data
    g_OnLinePayData.mHeaderSection.mVersion[1] = ALGORITHM_VERSION;  // use RSA2048-SHA1-PKCS1 to sign data
    g_OnLinePayData.mHeaderSection.mFrom = DATA_FROM_SERVICE;    // Data from service
    g_OnLinePayData.mHeaderSection.mTo = DATA_TO_CLIENT;      // Data to client
    g_OnLinePayData.mHeaderSection.mNum = FLAG_DATA_EXCHANGE_KEY;

    /** 2.2) Package data section */
    g_OnLinePayData.mDataSection.mPurpose = PURPOSE_FOR_PAY_OVER;
    g_OnLinePayData.mDataSection.mLength = l_PayoverData.mPayDataLen  + 8U;
    g_OnLinePayData.mDataSection.mPdata = (CHAR*)(&l_PayoverData);
  
    /** 3) Copy plain data into buffer */
    l_Ret = sizeof(OnLinePayHeaderSection);    //Length of header + mPurpose + mLength
    memcpy(pBuf, &g_OnLinePayData, l_Ret);

    /** 4) Put length and data content into bufffer */
    memcpy(&(pBuf[l_Ret]), &(g_OnLinePayData.mDataSection.mPurpose), sizeof(UINT16));
    l_Ret = l_Ret + sizeof(UINT16);

    memcpy(&(pBuf[l_Ret]), &(g_OnLinePayData.mDataSection.mLength), sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);
    
    memcpy(&(pBuf[l_Ret]), &(l_PayoverData.mPayDataLen), sizeof(UINT32));
    l_Ret = l_Ret + sizeof(UINT32);
    
    memcpy(&(pBuf[l_Ret]), g_PayOperComplete, sizeof(g_PayOperComplete) - 1);
    l_Ret = l_Ret + sizeof(g_PayOperComplete) - 1;

    
    /** 7) Return length of plain text data */
    return l_Ret;
}





/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for handle command.
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
int main(int argc, char *argv[])
{
    UINT32 l_Tmp =0U;
    CHAR l_Sign[256] = {0};
    CHAR l_hash[20] = {0};
    CHAR l_CipherData[256] = {0};


    if(0 == memcmp(argv[1], "hsone", 5))
    {
        l_handshakeone_analy(g_handshakeOneData, 256, argv[2]);
    }

    if(0 == memcmp(argv[1], "hstwo", 5))
    {
        memset(g_Output2048, 0, 256);
        l_Tmp = l_OnLinePayTaHandle_PackageHandshakeTwo(g_HandshakeTwoData, sizeof(g_HandshakeTwoData));
        printf("Plain text data:\n");
        g_Debug_Printf(g_HandshakeTwoData, 256);
        
        g_CryptoRsa_Encrypt(argv[2], g_HandshakeTwoData, 256U, l_Sign, RSA_NO_PADDING);
        memcpy(g_EncHSTwo, l_Sign, 256U);
        printf("Cipher text data:\n");
        g_Debug_Printf(g_EncHSTwo, 256);

        g_CryptoSha_shaOper(EN_OP_SHA1, g_EncHSTwo, 256U, l_hash);
        printf("hash data:\n");
        g_Debug_Printf(l_hash, 20);
        
        g_CryptoRsa_Sign(argv[3], l_hash, 20U, l_Sign, RSA_PKCS1_PADDING);
        memcpy(&(g_EncHSTwo[256]), l_Sign, 256U);
        printf("Signature data\n");
        g_Debug_Printf(l_Sign, 256);
        
        printf("Package data\n");
        g_Debug_Printf(g_EncHSTwo, 512);
    }

    if(0 == memcmp(argv[1], "hsthree", 7))
    {
        memset(g_Output2048, 0, 256);
        l_handshakethree_analy(g_Output2048, 256, argv[2], argv[3]);
        printf("%s\n", g_Output2048);
    }    


    if(0 == memcmp(argv[1], "payreq", 6))
    {
        memset(g_Output2048, 0, 256);
        l_paydata_analy(g_PayData, sizeof(g_PayData), argv[2]);
        printf("%s\n", g_Output2048);
    }    

    if(0 == memcmp(argv[1], "payover", 6))
    {
        
        l_Tmp = l_OnLinePayTaHandle_PackagePayOver(g_PayOverData, sizeof(g_PayOverData));
        printf("Plain text data:\n");
        g_Debug_Printf(g_PayOverData, 256);
        
        g_CryptoAes_encrypt(g_PayOverData, 256, EN_MODE_CBC, l_CipherData);
        printf("Cipher text data:\n");
        g_Debug_Printf(l_CipherData, 256);
        memcpy(g_PayOverData, l_CipherData, 256U);

        g_CryptoSha_shaOper(EN_OP_SHA1, l_CipherData, 256U, l_hash);
        printf("hash data:\n");
        g_Debug_Printf(l_hash, 20);
        
        g_CryptoRsa_Sign(argv[2], l_hash, 20U, l_Sign, RSA_PKCS1_PADDING);
        memcpy(&(g_PayOverData[256]), l_Sign, 256U);
        printf("Signature data\n");
        g_Debug_Printf(l_Sign, 256);
        
        printf("Package data\n");
        g_Debug_Printf(g_PayOverData, 512);
    }    

    
    return 0;
}





















/**
 * @}
 */