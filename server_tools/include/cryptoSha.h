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
 *               cryptoSha.h
 *
 * Filename      : cryptoSha.h
 * Programmer(s) : system BSP
 * Filename      : cryptoSha.h
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@whaley.cn
 * Create Time   : Thu 20 Aug 2015 03:02:07 AM EDT
 ****************************************************************************************
 */

#ifndef MOUDLE_SHA_H_
#define MOUDLE_SHA_H_




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
/* SHA operation type */
typedef enum
{
    EN_OP_SHA1 = 1,
    EN_OP_SHA224,
    EN_OP_SHA256,
    EN_OP_SHA384,
    EN_OP_SHA512,
    EN_OP_SHA_INVALID
}EN_SHA_MODE;


#ifndef MOUDLE_SHA_C_


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
void g_CryptoSha_shaOper(EN_SHA_MODE shaMode, CHAR* pInput, UINT32 inLen, CHAR* pOutput);
















#endif

#endif  /* MOUDLE_NAME_H*/
