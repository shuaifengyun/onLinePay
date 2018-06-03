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
 *               cryptoAes.h
 *
 * Filename      : cryptoAes.h
 * Programmer(s) : system BSP
 * Filename      : cryptoAes.h
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@whaley.cn
 * Create Time   : Thu 20 Aug 2015 03:01:45 AM EDT
 ****************************************************************************************
 */

#ifndef MOUDLE_AES_H_
#define MOUDLE_AES_H_




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
typedef enum
{
    EN_MODE_CBC = 1,
    EN_MODE_ECB,
    EN_MODE_CTR,
    EN_MODE_CBC_CTS,
    EN_MODE_INVALIE
}EN_AES_MODE;


typedef struct CtrState_s 
{ 
	unsigned char ivec[AES_BLOCK_SIZE];	 
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
}CtrState; 




#ifndef MOUDLE_AES_C_


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
extern void g_CryptoAes_encrypt(CHAR* pInput, UINT32 inLen, EN_AES_MODE aesMode, CHAR* pOutput);
extern void g_CryptoAes_decrypt(CHAR* pInput, UINT32 inLen, EN_AES_MODE aesMode, CHAR* pOutput);
extern void g_CryptoAes_SetKey(CHAR* randomOne, CHAR* randomTwo, CHAR* randomThree);



















#endif

#endif  /* MOUDLE_NAME_H*/
