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

LOG_MODULE_REGISTER(ecdsa, LOG_LEVEL_DBG);

/* ====================================================================== */
/*				Global variables/defines for the ECDSA example			  */

 
#define HASH_CHUNK_SIZE 1024
#define NRF_CRYPTO_EXAMPLE_ECDSA_PUBLIC_KEY_SIZE (65)
#define NRF_CRYPTO_EXAMPLE_ECDSA_SIGNATURE_SIZE (64)
#define NRF_CRYPTO_EXAMPLE_ECDSA_HASH_SIZE (32)

/* Below text is used as plaintext for signing/verification */
static uint8_t m_plain_text[5*1024] = { 
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur finibus vestibulum scelerisque. " 
	"Aenean nec elit nec risus egestas dapibus. Aliquam aliquet dictum facilisis. Ut auctor condimentum faucibus."
	" Vivamus nec felis nisl. Proin pellentesque magna at consectetur cursus. Sed blandit dapibus lorem et sodales."
	" Phasellus luctus ex eu turpis facilisis scelerisque. Quisque nisi enim, vehicula a eros vitae, rutrum porta nisi. "
	"Suspendisse sed euismod orci, et lacinia risus. Suspendisse potenti. Quisque at consectetur eros. Ut augue lectus, "
	"varius quis lorem et, cursus tristique ipsum. Quisque augue nulla, auctor vitae erat ac, euismod volutpat augue."
	" Maecenas tempor velit eu lorem pulvinar, consectetur scelerisque nulla sagittis. Vestibulum aliquam vel tellus ut"
	"dignissim. Nulla lobortis placerat turpis, sed egestas elit fringilla sed. Duis ornare, felis non varius bibendum, nisl nisi mollis justo, eget blandit nulla dui sit amet libero. Phasellus blandit justo scelerisque luctus tempus. In eu neque eu risus efficitur elementum."
    "Quisque sed elit in magna volutpat ultricies at at lacus. Curabitur vitae eros libero. Phasellus faucibus tempor felis vitae tristique. Cras laoreet urna sagittis purus aliquet, eu laoreet nisi ullamcorper. Mauris non tortor at orci elementum hendrerit et eu mauris. Fusce eu justo porttitor, gravida purus in, porttitor lectus. Ut faucibus molestie nisi, id interdum lacus euismod at. Fusce elit massa, aliquet id condimentum a, semper vel purus. Ut vel gravida augue. Nullam massa arcu, ornare finibus ornare vitae, faucibus quis risus."
"Nullam elit mauris, lobortis in hendrerit a, vestibulum et purus. Pellentesque in hendrerit erat, quis blandit nibh. Phasellus ut turpis ex. In hac habitasse platea dictumst. Mauris commodo felis neque, vel hendrerit massa porttitor convallis. Nam non ligula non nisl luctus pretium. Etiam fermentum laoreet gravida. Donec mattis risus ut facilisis cursus. Sed sit amet suscipit quam. Etiam imperdiet eleifend mi suscipit lacinia. Aliquam vel erat in ipsum volutpat."
};
#define NRF_CRYPTO_EXAMPLE_ECDSA_TEXT_SIZE (sizeof(m_plain_text))
static uint8_t m_pub_key[NRF_CRYPTO_EXAMPLE_ECDSA_PUBLIC_KEY_SIZE];

static uint8_t m_signature[NRF_CRYPTO_EXAMPLE_ECDSA_SIGNATURE_SIZE];
static uint8_t m_hash[NRF_CRYPTO_EXAMPLE_ECDSA_HASH_SIZE];

static psa_key_id_t keypair_id;
static psa_key_id_t pub_key_id;
/* ====================================================================== */


static int crypto_finish(void)
{
	psa_status_t status;

	/* Destroy the key handle */
	status = psa_destroy_key(keypair_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	status = psa_destroy_key(pub_key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

static int generate_ecdsa_keypair(void)
{
	psa_status_t status;
	size_t olen;

	LOG_INF("Generating random ECDSA keypair...");

	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	/* Configure the key attributes */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attributes, 256);

	/* Generate a random keypair. The keypair is not exposed to the application,
	 * we can use it to sign hashes.
	 */
	status = psa_generate_key(&key_attributes, &keypair_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_generate_key failed! (Error: %d)", status);
		return APP_ERROR;
	}
    LOG_INF("Key ID: %ld", keypair_id);

	/* Export the public key */
	status = psa_export_public_key(keypair_id, m_pub_key, sizeof(m_pub_key), &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_export_public_key failed! (Error: %d)", status);
		return APP_ERROR;
	}
	/* Reset key attributes and free any allocated resources. */
	psa_reset_key_attributes(&key_attributes);

	return APP_SUCCESS;
}

static int import_ecdsa_pub_key(void)
{
	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	/* Configure the key attributes */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attributes, 256);

	status = psa_import_key(&key_attributes, m_pub_key, sizeof(m_pub_key), &pub_key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_import_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Reset key attributes and free any allocated resources. */
	psa_reset_key_attributes(&key_attributes);

	return APP_SUCCESS;
}

static int compute_hash(void)
{
    psa_hash_operation_t hash_op = PSA_HASH_OPERATION_INIT;
    psa_status_t status;
    size_t i;
    size_t chunk_size;
    uint32_t output_len;

    /* Setup the hash operation */
    status = psa_hash_setup(&hash_op, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS) {
        LOG_INF("psa_hash_setup failed! (Error: %d)", status);
        return APP_ERROR;
    }

    /* Process data in chunks */
    for (i = 0; i < sizeof(m_plain_text); i += HASH_CHUNK_SIZE) {
        chunk_size = sizeof(m_plain_text) - i;
        if (chunk_size > HASH_CHUNK_SIZE) {
            chunk_size = HASH_CHUNK_SIZE;
        }

        status = psa_hash_update(&hash_op, &m_plain_text[i], chunk_size);
        if (status != PSA_SUCCESS) {
            LOG_INF("psa_hash_update failed! (Error: %d)", status);
            psa_hash_abort(&hash_op);
            return APP_ERROR;
        }
    }

    /* Finish the hash computation */
    status = psa_hash_finish(&hash_op, m_hash, sizeof(m_hash), &output_len);
    if (status != PSA_SUCCESS) {
        LOG_INF("psa_hash_finish failed! (Error: %d)", status);
        psa_hash_abort(&hash_op);
        return APP_ERROR;
    }

    return APP_SUCCESS;
}

static int sign_message(void)
{
	uint32_t output_len;
	psa_status_t status;
	int64_t end_time = 0;
    uint64_t start_tick, end_tick;
    start_tick =  k_uptime_ticks();
	int64_t start_time = k_uptime_get();
	LOG_INF("Signing a message using ECDSA...");
    /* Compute the hash of the message in chunks */
    status = compute_hash();
    if (status != APP_SUCCESS) {
        return APP_ERROR;
    }

	#ifdef CONFIG_TIMER_HAS_64BIT_CYCLE_COUNTER
	LOG_INF("64-bit cycle counter is enabled.");
	#else
	LOG_INF("64-bit cycle counter is NOT enabled.");
	#endif

	/* Sign the hash */
	status = psa_sign_hash(keypair_id,
			       PSA_ALG_ECDSA(PSA_ALG_SHA_256),
			       m_hash,
			       sizeof(m_hash),
			       m_signature,
			       sizeof(m_signature),
			       &output_len);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_sign_hash failed! (Error: %d)", status);
		return APP_ERROR;
	}

	end_time = k_uptime_get();
    end_tick = k_uptime_ticks();
    LOG_INF("Time taken to sign the message: %lld ticks. Ticks per seonds %lld ", (end_tick - start_tick), sys_clock_hw_cycles_per_sec());
	LOG_INF("Message signed successfully!");
	LOG_INF("Time taken to sign the message: %lld ms", (end_time - start_time));
	
	//PRINT_HEX("Plaintext", m_plain_text, sizeof(m_plain_text));
	//PRINT_HEX("SHA256 hash", m_hash, sizeof(m_hash));
	//PRINT_HEX("Signature", m_signature, sizeof(m_signature));

	return APP_SUCCESS;
}

static int verify_message(void)
{
	psa_status_t status;

	LOG_INF("Verifying ECDSA signature...");

	/* Verify the signature of the hash */
	status = psa_verify_hash(pub_key_id,
				 PSA_ALG_ECDSA(PSA_ALG_SHA_256),
				 m_hash,
				 sizeof(m_hash),
				 m_signature,
				 sizeof(m_signature));
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_verify_hash failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_INF("Signature verification was successful!");

	return APP_SUCCESS;
}

int ecdsa_main(void)
{
	int status;

	LOG_INF("Starting ECDSA example...");


	status = generate_ecdsa_keypair();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = import_ecdsa_pub_key();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = sign_message();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = verify_message();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = crypto_finish();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	LOG_INF(APP_SUCCESS_MESSAGE);

	return APP_SUCCESS;
}
