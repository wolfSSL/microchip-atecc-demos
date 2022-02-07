/* main.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>

#include <asf.h>
#include <delay.h>
#include <tcc.h>
#include <tcc_callback.h>
#include <stdio.h>

#include "conf_uart_serial.h"

#define MAXSZ              1024

/* Configure clock debug output pins */
//#define DEBUG_CLOCKS
#define USE_RTC_COUNTER

#ifdef USE_RTC_COUNTER
    #include <rtc_count_interrupt.h>
#else
    #include <rtc_calendar.h>
#endif

/* Driver instances */
static struct usart_module cdc_uart_module;
struct rtc_module rtc_instance;
#ifndef USE_RTC_COUNTER
    struct tcc_module tcc_instance;
#endif

/* Local Functions */
double current_time(int reset);
void HardFault_HandlerC(uint32_t *hardfault_args);

/* Hard fault handler */
void HardFault_HandlerC(uint32_t *hardfault_args)
{
    /* These are volatile to try and prevent the compiler/linker optimizing them
    away as the variables never actually get used.  If the debugger won't show the
    values of the variables, make them global my moving their declaration outside
    of this function. */
    volatile uint32_t stacked_r0;
	volatile uint32_t stacked_r1;
	volatile uint32_t stacked_r2;
	volatile uint32_t stacked_r3;
	volatile uint32_t stacked_r12;
	volatile uint32_t stacked_lr;
    volatile uint32_t stacked_pc;
	volatile uint32_t stacked_psr;
	volatile uint32_t _CFSR;
	volatile uint32_t _HFSR;
	volatile uint32_t _DFSR;
	volatile uint32_t _AFSR;
	volatile uint32_t _BFAR;
	volatile uint32_t _MMAR;

	stacked_r0 = ((uint32_t)hardfault_args[0]);
	stacked_r1 = ((uint32_t)hardfault_args[1]);
	stacked_r2 = ((uint32_t)hardfault_args[2]);
	stacked_r3 = ((uint32_t)hardfault_args[3]);
	stacked_r12 = ((uint32_t)hardfault_args[4]);
	stacked_lr = ((uint32_t)hardfault_args[5]);
	stacked_pc = ((uint32_t)hardfault_args[6]);
	stacked_psr = ((uint32_t)hardfault_args[7]);

    // Configurable Fault Status Register
    // Consists of MMSR, BFSR and UFSR
	_CFSR = (*((volatile uint32_t *)(0xE000ED28)));

	// Hard Fault Status Register
	_HFSR = (*((volatile uint32_t *)(0xE000ED2C)));

	// Debug Fault Status Register
	_DFSR = (*((volatile uint32_t *)(0xE000ED30)));

	// Auxiliary Fault Status Register
	_AFSR = (*((volatile uint32_t *)(0xE000ED3C)));

	// Read the Fault Address Registers. These may not contain valid values.
	// Check BFARVALID/MMARVALID to see if they are valid values
	// MemManage Fault Address Register
	_MMAR = (*((volatile uint32_t *)(0xE000ED34)));
	// Bus Fault Address Register
	_BFAR = (*((volatile uint32_t *)(0xE000ED38)));

    printf ("\n\nHard fault handler (all numbers in hex):\n");
    printf ("R0 = %x\n", (unsigned int)stacked_r0);
    printf ("R1 = %x\n", (unsigned int)stacked_r1);
    printf ("R2 = %x\n", (unsigned int)stacked_r2);
    printf ("R3 = %x\n", (unsigned int)stacked_r3);
    printf ("R12 = %x\n", (unsigned int)stacked_r12);
    printf ("LR [R14] = %x  subroutine call return address\n", (unsigned int)stacked_lr);
    printf ("PC [R15] = %x  program counter\n", (unsigned int)stacked_pc);
    printf ("PSR = %x\n", (unsigned int)stacked_psr);
    printf ("CFSR = %x\n", (unsigned int)_CFSR);
    printf ("HFSR = %x\n", (unsigned int)_HFSR);
    printf ("DFSR = %x\n", (unsigned int)_DFSR);
    printf ("AFSR = %x\n", (unsigned int)_AFSR);
    printf ("MMAR = %x\n", (unsigned int)_MMAR);
    printf ("BFAR = %x\n", (unsigned int)_BFAR);

    // Break into the debugger
	__asm("BKPT #0\n");
}

__attribute__( ( naked ) )
void HardFault_Handler(void)
{
	__asm(
		"  mov r0, #4          \n"
		"  mov r1, lr          \n"
		"  tst r0, r1          \n"
		"  beq using_msp       \n"
		"  mrs r0, psp         \n"
		"  b call_c            \n"
		"using_msp:            \n"
		"  mrs r0, msp         \n"
		"call_c:               \n"
		"  ldr r2, =HardFault_HandlerC \n"
		"  bx r2               \n"
	);
}

static uint32_t secondCount = 0;

#ifdef USE_RTC_COUNTER
static void rtc_overflow_callback(void)
{
	secondCount++;
    port_pin_toggle_output_level(LED0_PIN);
}
#else
static void tcc_callback_overflow(
		struct tcc_module *const module_inst)
{
	secondCount++;
    port_pin_toggle_output_level(LED0_PIN);
}
#endif

#ifndef USE_RTC_COUNTER
/**
 * Configure TCC
 */
static void configure_tcc(void)
{
	struct tcc_config tcc_conf;
	tcc_get_config_defaults(&tcc_conf, TCC0);

    /**
     * Timer period is 1ms = Prescaler(16) * Period(2000) / Clock(32khz).
     */
	tcc_conf.counter.clock_source = GCLK_GENERATOR_1;
	tcc_conf.counter.period = 2000;
	tcc_conf.counter.clock_prescaler = TCC_CLOCK_PRESCALER_DIV16;
	tcc_init(&tcc_instance, TCC0, &tcc_conf);
	tcc_enable(&tcc_instance);

	tcc_register_callback(&tcc_instance, tcc_callback_overflow, TCC_CALLBACK_OVERFLOW);
    tcc_enable_callback(&tcc_instance, TCC_CALLBACK_OVERFLOW);
}

/**
 * Configure RTC
 */
#define BUILD_SECOND (__TIME__[6] * 10 + __TIME__[7] - 528)
#define BUILD_MINUTE (__TIME__[3] * 10 + __TIME__[4] - 528)
#define BUILD_HOUR   (__TIME__[0] * 10 + __TIME__[1] - 528)

#define BUILD_DAY   (__DATE__[4] * 10 + __DATE__[5] - (__DATE__[4] == ' ' ? 368 : 528))
#define BUILD_YEAR  (__DATE__[7] * 1000 + __DATE__[8] * 100 + __DATE__[9] * 10 + __DATE__[10] - 53328)

#define BUILD_MONTH ((__DATE__[1]+__DATE__[2] == 207) ? 1  : (__DATE__[1]+__DATE__[2] == 199) ? 2  : \
                     (__DATE__[1]+__DATE__[2] == 211) ? 3  : (__DATE__[1]+__DATE__[2] == 226) ? 4  : \
                     (__DATE__[1]+__DATE__[2] == 218) ? 5  : (__DATE__[1]+__DATE__[2] == 227) ? 6  : \
                     (__DATE__[1]+__DATE__[2] == 225) ? 7  : (__DATE__[1]+__DATE__[2] == 220) ? 8  : \
                     (__DATE__[1]+__DATE__[2] == 213) ? 9  : (__DATE__[1]+__DATE__[2] == 215) ? 10 : \
                     (__DATE__[1]+__DATE__[2] == 229) ? 11 : (__DATE__[1]+__DATE__[2] == 200) ? 12 : 0)
static void configure_rtc_calendar(void)
{
	/* Initialize RTC in calendar mode. */
	struct rtc_calendar_config config_rtc_calendar;
	struct rtc_calendar_time time;

	rtc_calendar_get_config_defaults(&config_rtc_calendar);

#ifdef ENABLE_RTC_ALARM
	struct rtc_calendar_time alarm;
	rtc_calendar_get_time_defaults(&alarm);
	alarm.year   = 2013;
	alarm.month  = 1;
	alarm.day    = 1;
	alarm.hour   = 0;
	alarm.minute = 0;
	alarm.second = 4;
	config_rtc_calendar.alarm[0].time = alarm;
	config_rtc_calendar.alarm[0].mask = RTC_CALENDAR_ALARM_MASK_YEAR;
#endif
	config_rtc_calendar.clock_24h     = true;

	rtc_calendar_init(&rtc_instance, RTC, &config_rtc_calendar);
	rtc_calendar_enable(&rtc_instance);

	/* Set current time. */
	time.year   = BUILD_YEAR;
	time.month  = BUILD_MONTH;
	time.day    = BUILD_DAY;
	time.hour   = BUILD_HOUR;
	time.minute = BUILD_MINUTE;
	time.second = BUILD_SECOND;
	rtc_calendar_set_time(&rtc_instance, &time);
}

#else

static void configure_rtc_count(void)
{
	struct rtc_count_config config_rtc_count;
    rtc_count_get_config_defaults(&config_rtc_count);
	config_rtc_count.prescaler           = RTC_COUNT_PRESCALER_DIV_1; /* 1ms */
	config_rtc_count.mode                = RTC_COUNT_MODE_16BIT;
#ifdef FEATURE_RTC_CONTINUOUSLY_UPDATED
	config_rtc_count.continuously_update = true;
#endif

	rtc_count_init(&rtc_instance, RTC, &config_rtc_count);
	rtc_count_enable(&rtc_instance);

    rtc_count_set_period(&rtc_instance, 1000);

	rtc_count_register_callback(&rtc_instance, rtc_overflow_callback, RTC_COUNT_CALLBACK_OVERFLOW);
	rtc_count_enable_callback(&rtc_instance, RTC_COUNT_CALLBACK_OVERFLOW);
}

#endif

/**
 *  Configure UART console.
 */
static void configure_console(void)
{
	struct usart_config usart_conf;

	usart_get_config_defaults(&usart_conf);
	usart_conf.mux_setting = CONF_STDIO_MUX_SETTING;
	usart_conf.pinmux_pad0 = CONF_STDIO_PINMUX_PAD0;
	usart_conf.pinmux_pad1 = CONF_STDIO_PINMUX_PAD1;
	usart_conf.pinmux_pad2 = CONF_STDIO_PINMUX_PAD2;
	usart_conf.pinmux_pad3 = CONF_STDIO_PINMUX_PAD3;
	usart_conf.baudrate    = CONF_STDIO_BAUDRATE;

	stdio_serial_init(&cdc_uart_module, CONF_STDIO_USART_MODULE, &usart_conf);
	usart_enable(&cdc_uart_module);
}

#ifdef DEBUG_CLOCKS
static void set_pin_mux(uint32_t mux)
{
	struct system_pinmux_config pin_clk_conf;
	system_pinmux_get_config_defaults(&pin_clk_conf);
	pin_clk_conf.direction = PORT_PIN_DIR_OUTPUT;
	pin_clk_conf.input_pull = SYSTEM_PINMUX_PIN_PULL_NONE;
	pin_clk_conf.mux_position = mux & 0xFFFF;
	system_pinmux_pin_set_config(mux >> 16, &pin_clk_conf);
}
static void clock_debug_init(void)
{
    /* Output GCLK0 on PB22 */
    set_pin_mux(PINMUX_PB22H_GCLK_IO0);

    /* Output GCLK1 on PB23 */
    set_pin_mux(PINMUX_PB23H_GCLK_IO1);
}
#endif


/*------------------------------------------------------------------------*/
/* TLS CLIENT */
/*------------------------------------------------------------------------*/
static int CbIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int ret;

    (void)ssl;
    (void)ctx;

    ret = usart_read_buffer_wait(&cdc_uart_module, (unsigned char*)buf, sz);
    if (ret == STATUS_ERR_TIMEOUT)
        return WOLFSSL_CBIO_ERR_WANT_READ;

    return (ret == STATUS_OK) ? sz : WOLFSSL_CBIO_ERR_GENERAL;
}

static int CbIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int ret;

    (void)ssl;
    (void)ctx;

    ret = usart_write_buffer_wait(&cdc_uart_module, (unsigned char*)buf, sz);
    if (ret == STATUS_ERR_TIMEOUT)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;

    return (ret == STATUS_OK) ? sz : WOLFSSL_CBIO_ERR_GENERAL;
}

static int serial_client(void)
{
    char msg[] = "Hello WolfSSL!\r\n";
    char reply[MAXSZ];
    int ret, msgSz, error;
    WOLFSSL* ssl = NULL;
    WOLFSSL_CTX* ctx = NULL;

    wolfSSL_Init();

    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        printf("CTXnew failed.\n");
        goto fail;
    }

    /*------------------------------------------------------------------------*/
    /* ECDHE-ECDSA */
    /*------------------------------------------------------------------------*/
    /*--------------------*/
    /* for peer auth use: */
    /*--------------------*/
    //    wolfSSL_CTX_load_verify_buffer(ctx, rsa_key_der_1024,
    //                                    sizeof_rsa_key_der_1024, SSL_FILETYPE_ASN1);
    //    wolfSSL_CTX_load_verify_buffer(ctx, server_cert_der_1024,
    //                                    sizeof_server_cert_der_1024, SSL_FILETYPE_ASN1);
    /*---------------------*/
    /* for no peer auth:   */
    /*---------------------*/
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
    /*---------------------*/
    /* end peer auth option*/
    /*---------------------*/
    if ((ret = wolfSSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256"))
                                                             != SSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        printf("CTXset_cipher_list failed, error: %d\n", ret);
        goto fail;
    }
    /*------------------------------------------------------------------------*/
    /* END CIPHER SUITE OPTIONS */
    /*------------------------------------------------------------------------*/
    wolfSSL_SetIORecv(ctx, CbIORecv);
    wolfSSL_SetIOSend(ctx, CbIOSend);

    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        error = wolfSSL_get_error(ssl, 0);
        printf("wolfSSL_new failed %d\n", error);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    /* non blocking accept and connect */
    ret = SSL_FAILURE;

    while (ret != SSL_SUCCESS) {
        /* client connect */
        ret = wolfSSL_connect(ssl);
        error = wolfSSL_get_error(ssl, 0);
        if (ret != SSL_SUCCESS) {
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                /* Fail */
                printf("wolfSSL connect failed with return code %d\n", error);
                goto fail;
            }
        }
        /* Success */
    }

    /* read and write */
    while (1) {
        /* client send/read */
        msgSz = sizeof(msg);
        ret   = wolfSSL_write(ssl, msg, msgSz);
        error = wolfSSL_get_error(ssl, 0);
        if (ret != msgSz) {
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                /* Write failed */
                goto fail;
            }
        }
        /* Write succeeded */
        break;
    }

    while (1) {
        ret = wolfSSL_read(ssl, reply, sizeof(reply) - 1);
        error = wolfSSL_get_error(ssl, 0);
        if (ret < 0) {
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                /* Can put print here, the server enters a loop waiting to read
                 * a confirmation message at this point */
                //                printf("client read failed\n");
                goto fail;
            }
            continue;
        }
        else {
            /* Can put print here, the server enters a loop waiting to read
             * a confirmation message at this point */
            reply[ret] = '\0';
            //            printf("Client Received Reply: %s\n", reply);
            break;
        }

    }

    return 0;

fail:
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return -1;
}



int main(void)
{
	const uint8_t welcomeStr[] = "Atmel SAMD21 wolfSSL Client\r\n";
	struct port_config pin;

	/* Initialize system */
	system_init();
    delay_init();

#ifdef DEBUG_CLOCKS
    clock_debug_init();
#endif

	configure_console();

#ifdef USE_RTC_COUNTER
    configure_rtc_count();
#else
    configure_tcc();
    configure_rtc_calendar();
#endif

    system_interrupt_enable_global();

    /* Configure LED */
	port_get_config_defaults(&pin);
	pin.direction = PORT_PIN_DIR_OUTPUT;
	port_pin_set_config(LED0_PIN, &pin);
	port_pin_set_output_level(LED0_PIN, LED0_INACTIVE);

    /* Send welcome message to UART */
	usart_write_buffer_wait(&cdc_uart_module, welcomeStr, sizeof(welcomeStr));

    /* start TLS client and use UART */
    return serial_client();
}

static uint32_t hw_get_time_sec(void)
{
#ifdef USE_RTC_COUNTER
    uint32_t timer = rtc_count_get_count(&rtc_instance);
#else
    uint32_t timer = tcc_get_count_value(&tcc_instance);
    timer /= 2;
#endif
    return timer;
}

double current_time(int reset)
{
    uint32_t timer = hw_get_time_sec();
    //printf("seconds=%u, timer=%u\n", secondCount, timer);
    return (double)secondCount + (((double)timer) / 1000);
}
