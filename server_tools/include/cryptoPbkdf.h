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
 *               cryptoPbkdf.h
 *
 * Filename      : cryptoPbkdf.h
 * Programmer(s) : system BSP
 * Filename      : cryptoPbkdf.h
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@whaley.cn
 * Create Time   : Fri 21 Aug 2015 07:02:21 AM EDT
 ****************************************************************************************
 */

#ifndef MOUDLE_PBKDF_H_
#define MOUDLE_PBKDF_H_




/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "cryptoType.h"




/*
 *******************************************************************************
 *                  MACRO DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/


#ifndef MOUDLE_PBKDF_C_


/*
 *******************************************************************************
 *                      VARIABLES SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                      FUNCTIONS SUPPLIED BY THIS MODULE
 *******************************************************************************
*/
extern void g_CryptoPbkdf_PbkdfOperation(CHAR* pwd,int pLen, CHAR* salt, int sLen, int count,int dkLen, CHAR* output);
extern void g_CryptoRandom_GenRandomString(CHAR* buf, UINT32 length);
extern void g_Test_hmac(int len);
extern UINT32 g_CryptoBase64_enc(const char *encoded, int encodedLength, char *decoded);
extern UINT32 g_CryptoBase64_dec(unsigned char *input, int length, char* output);















#endif

#endif  /* MOUDLE_NAME_H*/
