/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <zephyr/shell/shell.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#define APP_SUCCESS		(0)
#define APP_ERROR		(-1)
#define APP_SUCCESS_MESSAGE "Example finished successfully!"
#define APP_ERROR_MESSAGE "Example exited with error!"

#define PRINT_HEX(p_label, p_text, len)\
	({\
		LOG_INF("---- %s (len: %u): ----", p_label, len);\
		LOG_HEXDUMP_INF(p_text, len, "Content:");\
		LOG_INF("---- %s end  ----", p_label);\
	})

LOG_MODULE_REGISTER(hmac, LOG_LEVEL_DBG);

/* ====================================================================== */
/*				Global variables/defines for the HMAC example			  */

#define NRF_CRYPTO_EXAMPLE_HMAC_TEXT_SIZE (256)
#define NRF_CRYPTO_EXAMPLE_HMAC_KEY_SIZE (32)

/* Below text is used as plaintext for signing/verifiction */
static uint8_t m_plain_text[NRF_CRYPTO_EXAMPLE_HMAC_TEXT_SIZE] = {
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur finibus vestibulum scelerisque. " 
	"Aenean nec elit nec risus egestas dapibus. Aliquam aliquet dictum facilisis. Ut auctor condimentum faucibus. sdsddsdsdsd dfdfdfdfd efdfdfdf fdfdfdfd"
};


static uint8_t hmac[NRF_CRYPTO_EXAMPLE_HMAC_KEY_SIZE];

static psa_key_id_t key_id;
/* ====================================================================== */


static  int crypto_finish(void)
{
	psa_status_t status;

	/* Destroy the key handle */
	status = psa_destroy_key(key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

static int generate_key(void)
{
	psa_status_t status;

	LOG_INF("Generating random HMAC key...");

	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_usage_flags(&key_attributes,
				PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&key_attributes, 256);

	/* Generate a random key. The key is not exposed to the application,
	 * we can use it to encrypt/decrypt using the key handle
	 */
	status = psa_generate_key(&key_attributes, &key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_generate_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* After the key handle is acquired the attributes are not needed */
	psa_reset_key_attributes(&key_attributes);

	LOG_INF("HMAC key generated successfully! %u", key_id);

	return APP_SUCCESS;
}

static int hmac_sign(void)
{
	uint32_t olen;
	psa_status_t status;
	psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    int64_t start_time = k_uptime_get();
    int64_t end_time = 0;
    uint64_t start_tick, end_tick;
    start_tick =  k_cycle_get_64();


	LOG_INF("Signing using HMAC ...");

	/* Initialize the HMAC signing operation */
	status = psa_mac_sign_setup(&operation, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_mac_sign_setup failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Perform the HMAC signing */
	status = psa_mac_update(&operation, m_plain_text, sizeof(m_plain_text));
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_mac_update failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Finalize the HMAC signing */
	status = psa_mac_sign_finish(&operation, hmac, sizeof(hmac), &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_mac_sign_finish failed! (Error: %d)", status);
		return APP_ERROR;
	}
    end_time = k_uptime_get();
    end_tick = k_cycle_get_64();
    LOG_INF("Time taken to sign the message: %lld ms", (end_time - start_time));
    LOG_INF("Time taken to sign the message: %lld ticks. Ticks per seonds %lld ", (end_tick - start_tick), sys_clock_hw_cycles_per_sec());
	LOG_INF("Signing successful!");
	PRINT_HEX("Plaintext", m_plain_text, sizeof(m_plain_text));
	PRINT_HEX("HMAC", hmac, sizeof(hmac));

	return APP_SUCCESS;
}

static  int hmac_verify(void)
{
	psa_status_t status;
	psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;

	LOG_INF("Verifying the HMAC signature...");

	/* Initialize the HMAC verification operation */
	status = psa_mac_verify_setup(&operation, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_mac_verify_setup failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Perform the HMAC verification */
	status = psa_mac_update(&operation, m_plain_text, sizeof(m_plain_text));
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_mac_update failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Finalize the HMAC verification */
	status = psa_mac_verify_finish(&operation, hmac, sizeof(hmac));
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_mac_verify_finish failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_INF("HMAC verified successfully!");

	return APP_SUCCESS;
}

int hmac_init(void)
{
	int status = generate_key();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}
	return APP_SUCCESS;
}

int hmac_term(void)
{
	int status = crypto_finish();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}
}

int hmac_main(void)
{
	int status;


	status = hmac_sign();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = hmac_verify();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}



	LOG_INF(APP_SUCCESS_MESSAGE);

	return APP_SUCCESS;
}

static int test_hmac(const struct shell *shell, size_t argc, char **argv)
{
    // The first argument (argv[0]) is always the command name itself
    hmac_main();
    return 0;
}

static int shell_hmac_init(const struct shell *shell, size_t argc, char **argv)
{
    // The first argument (argv[0]) is always the command name itself
    hmac_init();
    return 0;
}

static int shell_hmac_term(const struct shell *shell, size_t argc, char **argv)
{
	// The first argument (argv[0]) is always the command name itself
	hmac_term();
	return 0;
}

SHELL_CMD_REGISTER(
    test_hmac,         /* Command name (must be unique) */
    NULL,          /* Subcommands array (NULL for a simple root command) */
    "testhmac", /* Command help string */
    test_hmac /* Pointer to the handler function */
);

SHELL_CMD_REGISTER(
    test_hmac_init,         /* Command name (must be unique) */
    NULL,          /* Subcommands array (NULL for a simple root command) */
    "hmac init", /* Command help string */
    shell_hmac_init /* Pointer to the handler function */
);

SHELL_CMD_REGISTER(
    shell_hmac_term,         /* Command name (must be unique) */
    NULL,          /* Subcommands array (NULL for a simple root command) */
    "hmac term", /* Command help string */
    shell_hmac_term /* Pointer to the handler function */
);