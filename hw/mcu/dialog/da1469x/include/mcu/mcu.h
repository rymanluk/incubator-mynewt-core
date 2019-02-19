/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef __MCU_MCU_H_
#define __MCU_MCU_H_

#ifdef __cplusplus
extern "C" {
#endif

#define sec_text_ram_core   __attribute__((section(".text_ram"))) __attribute__((noinline))

/**
* \brief GPIO function
*
*/
typedef enum {
    MCU_GPIO_FUNC_GPIO = 0,                  /**< GPIO */
    MCU_GPIO_FUNC_UART_RX = 1,               /**< GPIO as UART RX */
    MCU_GPIO_FUNC_UART_TX = 2,               /**< GPIO as UART TX */
    MCU_GPIO_FUNC_UART2_RX = 3,              /**< GPIO as UART2 RX */
    MCU_GPIO_FUNC_UART2_TX = 4,              /**< GPIO as UART2 TX */
    MCU_GPIO_FUNC_UART2_CTSN = 5,            /**< GPIO as UART2 CTSN */
    MCU_GPIO_FUNC_UART2_RTSN = 6,            /**< GPIO as UART2 RTSN */
    MCU_GPIO_FUNC_UART3_RX = 7,              /**< GPIO as UART3 RX */
    MCU_GPIO_FUNC_UART3_TX = 8,              /**< GPIO as UART3 TX */
    MCU_GPIO_FUNC_UART3_CTSN = 9,            /**< GPIO as UART3 CTSN */
    MCU_GPIO_FUNC_UART3_RTSN = 10,           /**< GPIO as UART3 RTSN */
    MCU_GPIO_FUNC_ISO_CLK = 11,              /**< GPIO as ISO CLK */
    MCU_GPIO_FUNC_ISO_DATA = 12,             /**< GPIO as ISO DATA */
    MCU_GPIO_FUNC_SPI_DI = 13,               /**< GPIO as SPI DI */
    MCU_GPIO_FUNC_SPI_DO = 14,               /**< GPIO as SPI DO */
    MCU_GPIO_FUNC_SPI_CLK = 15,              /**< GPIO as SPI CLK */
    MCU_GPIO_FUNC_SPI_EN = 16,               /**< GPIO as SPI EN */
    MCU_GPIO_FUNC_SPI2_DI = 17,              /**< GPIO as SPI2 DI */
    MCU_GPIO_FUNC_SPI2_DO = 18,              /**< GPIO as SPI2 DO */
    MCU_GPIO_FUNC_SPI2_CLK = 19,             /**< GPIO as SPI2 CLK */
    MCU_GPIO_FUNC_SPI2_EN = 20,              /**< GPIO as SPI2 EN */
    MCU_GPIO_FUNC_I2C_SCL = 21,              /**< GPIO as I2C SCL */
    MCU_GPIO_FUNC_I2C_SDA = 22,              /**< GPIO as I2C SDA */
    MCU_GPIO_FUNC_I2C2_SCL = 23,             /**< GPIO as I2C2 SCL */
    MCU_GPIO_FUNC_I2C2_SDA = 24,             /**< GPIO as I2C2 SDA */
    MCU_GPIO_FUNC_USB_SOF = 25,              /**< GPIO as USB SOF */
    MCU_GPIO_FUNC_ADC = 26,                  /**< GPIO as ADC (dedicated pin) */
    MCU_GPIO_FUNC_USB = 27,                  /**< GPIO as USB */
    MCU_GPIO_FUNC_PCM_DI = 28,               /**< GPIO as PCM DI */
    MCU_GPIO_FUNC_PCM_DO = 29,               /**< GPIO as PCM DO */
    MCU_GPIO_FUNC_PCM_FSC = 30,              /**< GPIO as PCM FSC */
    MCU_GPIO_FUNC_PCM_CLK = 31,              /**< GPIO as PCM CLK */
    MCU_GPIO_FUNC_PDM_DATA = 32,             /**< GPIO as PDM DATA */
    MCU_GPIO_FUNC_PDM_CLK = 33,              /**< GPIO as PDM CLK */
    MCU_GPIO_FUNC_COEX_EXT_ACT = 34,         /**< GPIO as COEX EXT ACT0 */
    MCU_GPIO_FUNC_COEX_SMART_ACT = 35,       /**< GPIO as COEX SMART ACT */
    MCU_GPIO_FUNC_COEX_SMART_PRI = 36,       /**< GPIO as COEX SMART PRI */
    MCU_GPIO_FUNC_PORT0_DCF = 37,            /**< GPIO as PORT0 DCF */
    MCU_GPIO_FUNC_PORT1_DCF = 38,            /**< GPIO as PORT1 DCF */
    MCU_GPIO_FUNC_PORT2_DCF = 39,            /**< GPIO as PORT2 DCF */
    MCU_GPIO_FUNC_PORT3_DCF = 40,            /**< GPIO as PORT3 DCF */
    MCU_GPIO_FUNC_PORT4_DCF = 41,            /**< GPIO as PORT4 DCF */
    MCU_GPIO_FUNC_CLOCK = 42,                /**< GPIO as CLOCK */
    MCU_GPIO_FUNC_PG = 43,                   /**< GPIO as PG */
    MCU_GPIO_FUNC_LCD = 44,                  /**< GPIO as LCD */
    MCU_GPIO_FUNC_LCD_SPI_DC = 45,           /**< GPIO as LCD SPI DC */
    MCU_GPIO_FUNC_LCD_SPI_DO = 46,           /**< GPIO as LCD SPI DO */
    MCU_GPIO_FUNC_LCD_SPI_CLK = 47,          /**< GPIO as LCD SPI CLK */
    MCU_GPIO_FUNC_LCD_SPI_EN = 48,           /**< GPIO as LCD SPI EN */
    MCU_GPIO_FUNC_TIM_PWM = 49,              /**< GPIO as TIM PWM */
    MCU_GPIO_FUNC_TIM2_PWM = 50,             /**< GPIO as TIM2 PWM */
    MCU_GPIO_FUNC_TIM_1SHOT = 51,            /**< GPIO as TIM 1SHOT */
    MCU_GPIO_FUNC_TIM2_1SHOT = 52,           /**< GPIO as TIM2 1SHOT */
    MCU_GPIO_FUNC_TIM3_PWM = 53,             /**< GPIO as TIM3 PWM */
    MCU_GPIO_FUNC_TIM4_PWM = 54,             /**< GPIO as TIM4 PWM */
    MCU_GPIO_FUNC_AGC_EXT = 55,              /**< GPIO as AGC EXT */
    MCU_GPIO_FUNC_CMAC_DIAG0 = 56,           /**< GPIO as CMAC DIAG0 */
    MCU_GPIO_FUNC_CMAC_DIAG1 = 57,           /**< GPIO as CMAC DIAG1 */
    MCU_GPIO_FUNC_CMAC_DIAG2 = 58,           /**< GPIO as CMAC DIAG2 */
    MCU_GPIO_FUNC_CMAC_DIAGX = 59,           /**< GPIO as CMAC DIAGX */
    MCU_GPIO_FUNC_LAST,
} mcu_gpio_func;

#define MCU_GPIO_MODE_INPUT                 0x000    /**< GPIO as an input */
#define MCU_GPIO_MODE_INPUT_PULLUP          0x100    /**< GPIO as an input with pull-up */
#define MCU_GPIO_MODE_INPUT_PULLDOWN        0x200    /**< GPIO as an input with pull-down */
#define MCU_GPIO_MODE_OUTPUT                0x300    /**< GPIO as an output */
#define MCU_GPIO_MODE_OUTPUT_OPEN_DRAIN     0x700    /**< GPIO as an open-drain output */

void mcu_gpio_set_pin_function(int pin, int mode, mcu_gpio_func func);

#define MCU_MEM_QSPIF_M_START_ADDRESS   (0x16000000)
#define MCU_MEM_QSPIF_M_END_ADDRESS     (0x18000000)
#define MCU_MEM_SYSRAM_START_ADDRESS    (0x20000000)
#define MCU_MEM_SYSRAM_END_ADDRESS      (0x20080000)

#ifdef __cplusplus
}
#endif

#endif /* __MCU_MCU_H_ */

