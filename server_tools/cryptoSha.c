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
 *               cryptoSha.c
 *
 * Filename      : cryptoSha.c
 * Programmer(s) : system BSP
 * Filename      : cryptoSha.c
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@whaley.cn
 * Create Time   : Thu 20 Aug 2015 03:02:00 AM EDT
 ****************************************************************************************
 */

#define MOUDLE_SHA_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "cryptoType.h"
#include "cryptoSha.h"
#include "cryptoDebug.h"




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





/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/
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
void g_CryptoSha_shaOper(EN_SHA_MODE shaMode, CHAR* pInput, UINT32 inLen, CHAR* pOutput)
{
    switch(shaMode)
    {
        case EN_OP_SHA1:
            SHA1(pInput, inLen, pOutput);
            break;
        case EN_OP_SHA224:
            SHA224(pInput, inLen, pOutput);
            break;        
        case EN_OP_SHA256:
            SHA256(pInput, inLen, pOutput);
            break;        
        case EN_OP_SHA384:
            SHA384(pInput, inLen, pOutput);
            break;        
        case EN_OP_SHA512:
            SHA512(pInput, inLen, pOutput);
            break;        
        default:
            printf("ERROR: invalid sha mode\n");
            break;        
    }
}



















/**
 * @}
 */
