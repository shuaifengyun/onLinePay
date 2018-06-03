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
 *               cryptoRsa.h
 *
 * Filename      : cryptoRsa.h
 * Programmer(s) : system BSP
 * Filename      : cryptoRsa.h
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@whaley.cn
 * Create Time   : Thu 20 Aug 2015 03:01:54 AM EDT
 ****************************************************************************************
 */

#ifndef MOUDLE_RSA_H_
#define MOUDLE_RSA_H_




/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/





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
/* RSA operation type */
typedef enum
{
    EN_OP_RSA_ENCRYPT = 1,
    EN_OP_RSA_DECRYPT,
    EN_OP_RSA_SIGN,
    EN_OP_RSA_VERIFY,
    EN_OP_RSA_INVALID
}EN_RSA_OPERATION_ACTION;

/* RSA key type(1024,2048) */
typedef enum
{
    EN_KEY_1024 = 1,
    EN_KEY_2048,
    EN_KEY_INVALID
}EN_RSA_KEY_TYPE;

/* RSA padding type */
typedef enum
{
    EN_PADDING_PKCS1 = 1,
    EN_PADDING_PKCS7,
    EN_PADDING_NO,
    EN_PADDING_INVALID
}EN_RSA_PADDING_TYPE;





#ifndef MOUDLE_RSA_C_


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
extern int g_CryptoRsa_Encrypt(CHAR* pubKeyFile, CHAR* inputBuf, UINT32 inLen, CHAR* outputBuf, int padType);
extern int g_CryptoRsa_Decrypt(CHAR* priKeyFile, CHAR* inputBuf, UINT32 inLen, CHAR* outputBuf, int padType);
extern int g_CryptoRsa_Sign(CHAR* priKeyFile, CHAR* inputBuf, UINT32 inLen, CHAR* outputBuf, int padType);
extern int g_CryptoRsa_Verify(CHAR* pubKeyFile, CHAR* RawBuf, UINT32 rawLen, CHAR* signBuf, int padType);


















#endif

#endif  /* MOUDLE_NAME_H*/
