#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>

#include <ph_NxpBuild.h>
#include <ph_Status.h>

#include <phpalI14443p3a.h>
#include <phpalI14443p4.h>
#include <phalMfc.h>

static phStatus_t initLayers();

static phStatus_t status;
static uint8_t bHalBufferReader[0x40];

static phbalReg_R_Pi_spi_DataParams_t bal;
static phhalHw_Rc523_DataParams_t hal;
static phpalI14443p3a_Sw_DataParams_t palI14443p3a;
static phpalI14443p4_Sw_DataParams_t palI14443p4;
static phpalMifare_Sw_DataParams_t palMifare;
static phalMfc_Sw_DataParams_t alMfc;

phStatus_t initLayers()
{
  /* Initialize the Reader BAL (Bus Abstraction Layer) component */
  PH_CHECK_SUCCESS_FCT(status, phbalReg_R_Pi_spi_Init(&bal, sizeof(phbalReg_R_Pi_spi_DataParams_t)));
  PH_CHECK_SUCCESS_FCT(status, phbalReg_OpenPort((void *)&bal));

  /* we have a board with PN512,
   * but on the software point of view,
   * it's compatible to the RC523 */
  PH_CHECK_SUCCESS_FCT(status, phhalHw_Rc523_Init(&hal,
      sizeof(phhalHw_Rc523_DataParams_t),
      (void *)&bal,
      0,
      bHalBufferReader,
      sizeof(bHalBufferReader),
      bHalBufferReader,
      sizeof(bHalBufferReader)));

  /* Set the HAL configuration to SPI */
  PH_CHECK_SUCCESS_FCT(status, phhalHw_SetConfig(&hal, PHHAL_HW_CONFIG_BAL_CONNECTION,
      PHHAL_HW_BAL_CONNECTION_SPI));

  PH_CHECK_SUCCESS_FCT(status, phpalI14443p3a_Sw_Init(&palI14443p3a,
        sizeof(phpalI14443p3a_Sw_DataParams_t), &hal));

  PH_CHECK_SUCCESS_FCT(status, phpalI14443p4_Sw_Init(&palI14443p4,
        sizeof(phpalI14443p4_Sw_DataParams_t), &hal));

  PH_CHECK_SUCCESS_FCT(status, phpalMifare_Sw_Init(&palMifare,
        sizeof(phpalMifare_Sw_DataParams_t), &hal, &palI14443p4));

  PH_CHECK_SUCCESS_FCT(status, phalMfc_Sw_Init(&alMfc,
        sizeof(phalMfc_Sw_DataParams_t), &palMifare, NULL));

  return PH_ERR_SUCCESS;
}

phStatus_t search_card(uint8_t * pUid, uint8_t * pLength, uint8_t * pSak, uint8_t * pNbCards) {
  PH_CHECK_SUCCESS_FCT(status, phhalHw_FieldReset(&hal));

  PH_CHECK_SUCCESS_FCT(status, phhalHw_ApplyProtocolSettings(&hal,
        PHHAL_HW_CARDTYPE_ISO14443A));

  PH_CHECK_SUCCESS_FCT(status, phpalI14443p3a_ActivateCard(&palI14443p3a, NULL, 0x00, pUid,
      pLength, pSak, pNbCards));

  return PH_ERR_SUCCESS;
}
phStatus_t readSector(uint8_t sector_id, uint8_t * key, uint8_t key_type, uint8_t * bUid, uint8_t * data) {
  uint8_t block = sector_id << 2;
  PH_CHECK_SUCCESS_FCT(status,
      phhalHw_MfcAuthenticate(&hal, block, key_type, key, bUid));
  PH_CHECK_SUCCESS_FCT(status, phalMfc_Read(&alMfc, block + 0, &data[0 * 16]));
  PH_CHECK_SUCCESS_FCT(status, phalMfc_Read(&alMfc, block + 1, &data[1 * 16]));
  PH_CHECK_SUCCESS_FCT(status, phalMfc_Read(&alMfc, block + 2, &data[2 * 16]));
  PH_CHECK_SUCCESS_FCT(status, phalMfc_Read(&alMfc, block + 3, &data[3 * 16]));
  return PH_ERR_SUCCESS;
}

phStatus_t forceReadSector(uint8_t sector_id, uint8_t ** keys, uint16_t nbKeys, uint8_t * data) {
  uint8_t bSak[1];
  uint8_t bUid[10];
  uint8_t bNbCards;
  uint8_t bLength;
  uint16_t i;
  PH_CHECK_SUCCESS_FCT(status, search_card(bUid, &bLength, bSak, &bNbCards));
  for (i = 0; i < nbKeys; i++) {
    if (readSector(sector_id, keys[i], PHAL_MFC_KEYA, bUid, data) == PH_ERR_SUCCESS)
      return PH_ERR_SUCCESS;
    PH_CHECK_SUCCESS_FCT(status, search_card(bUid, &bLength, bSak, &bNbCards));
    if (readSector(sector_id, keys[i], PHAL_MFC_KEYB, bUid, data) == PH_ERR_SUCCESS)
      return PH_ERR_SUCCESS;
    PH_CHECK_SUCCESS_FCT(status, search_card(bUid, &bLength, bSak, &bNbCards));
  }
  return PH_ERR_AUTH_ERROR;
}

phStatus_t writeBlock(uint8_t block, uint8_t * key, uint8_t key_type, uint8_t * bUid, uint8_t * data) {
  PH_CHECK_SUCCESS_FCT(status,
      phhalHw_MfcAuthenticate(&hal, block, key_type, key, bUid));
  PH_CHECK_SUCCESS_FCT(status, phalMfc_Write(&alMfc, block, &data[0]));
  return PH_ERR_SUCCESS;
}

phStatus_t forceWriteBlock(uint8_t block_id, uint8_t ** keys, uint16_t nbKeys, uint8_t * data) {
  uint8_t bSak[1];
  uint8_t bUid[10];
  uint8_t bNbCards;
  uint8_t bLength;
  uint16_t i;
  PH_CHECK_SUCCESS_FCT(status, search_card(bUid, &bLength, bSak, &bNbCards));
  for (i = 0; i < nbKeys; i++) {
    if (writeBlock(block_id, keys[i], PHAL_MFC_KEYA, bUid, data) == PH_ERR_SUCCESS)
      return PH_ERR_SUCCESS;
    PH_CHECK_SUCCESS_FCT(status, search_card(bUid, &bLength, bSak, &bNbCards));
    if (writeBlock(block_id, keys[i], PHAL_MFC_KEYB, bUid, data) == PH_ERR_SUCCESS)
      return PH_ERR_SUCCESS;
    PH_CHECK_SUCCESS_FCT(status, search_card(bUid, &bLength, bSak, &bNbCards));
  }
  return PH_ERR_AUTH_ERROR;
}

int main(void)
{
  static uint8_t bSak[1];
  static uint8_t bUid[10];
  static uint8_t bMoreCardsAvailable;
  static uint8_t bLength;

  PH_CHECK_SUCCESS_FCT(status, initLayers());

  uint8_t key1[6] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};
  uint8_t key2[6] = {0xb4, 0xce, 0x31, 0x75, 0x17, 0xda};
  uint8_t key3[6] = {0xfe, 0xa7, 0xe1, 0x1b, 0x47, 0xb3};
  uint8_t key4[6] = {0x58, 0x23, 0xc4, 0xec, 0xfa, 0x01};
  uint8_t key5[6] = {0x8f, 0xef, 0x64, 0x3e, 0x56, 0x04};
  uint8_t key6[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  uint8_t key7[6] = {0x04, 0x91, 0xa7, 0x84, 0x17, 0x1a};
  static const uint16_t nbKeys = 7;
  uint8_t * keys[7] = {key1, key2, key3, key4, key5, key6, key7};

  uint8_t data[16] = {0};
  /* data[0] = 0x42; */
  /* data[1] = 0x13; */
  /* data[2] = 0x37; */
  /* data[3] = 0x03; */
  /* data[4] = 0x14; */
  /* data[5] = 0x15; */
  /* forceWriteBlock(42, keys, nbKeys, data); */

  uint8_t sector = 43;
  uint8_t buffer[64];
  uint8_t i;
  for (sector = 0; sector < 16; sector++) {
    /* printf("Sector %02d:\n", sector); */
    if(forceReadSector(sector, keys, nbKeys, buffer) == PH_ERR_SUCCESS) {
      for (i = 0; i < 64; i++) {
        printf("%02X ", buffer[i]);
        if ((i + 1) % 16 == 0)
          printf("\n");
      }
    }
    else {
      for (i = 0; i < 64; i++) {
        printf("xx ");
        if ((i + 1) % 16 == 0)
          printf("\n");
      }
    }
    printf("\n");
  }

  return 0;
}
