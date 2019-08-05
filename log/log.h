
#include <stdint.h>

enum tpm_type {
	TPM_12,
	TPM_20,
};

enum tpmi_alg_hash {
	TPM_ALG_SHA1	= 0x0004,
	TPM_ALG_SHA256	= 0x000B,
	TPM_ALG_SHA384	= 0x000C,
	TPM_ALG_SHA512	= 0x000D,
	TPM_ALG_SM3_256 = 0x0012,
	TPM_ALG_SM4	= 0x0013,
};

#define EVTYPE_BASE 0x400
#define EVTYPE_PCRMAPPING 0x401 

struct heap_ext_data_element {
	uint32_t type;
	uint32_t size;
	uint8_t data[];
};

#define MAX_EVENT_LOG_SIZE 20480
/*
 * In practice the log buffer is 20KiB, therefore limit a pcr event's
 * total size to 1KiB which allows at least 20 distinct events.
 */
#define MAX_PCR_EVENT_SIZE 1024

#define HEAP_EXTDATA_TYPE_END 0

#define HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR 5

struct heap_tpm_event_log_element {
	uint64_t event_log_phys_addr;
};

struct tcg_pcr_event {
	uint32_t pcr_index;
	uint32_t type;
	uint8_t digest[20];
	uint32_t size;
	uint8_t data[];
};

#define EVTLOG_SIGNATURE "TXT Event Container\0"
#define EVTLOG_SIGNATURE_SIZE 20
#define EVTLOG_CNTNR_MAJOR_VER 1
#define EVTLOG_CNTNR_MINOR_VER 0
#define EVTLOG_EVT_MAJOR_VER 1
#define EVTLOG_EVT_MINOR_VER 0
#define EVTLOG_CNTNR_SIZE 48

struct event_log_container {
    uint8_t signature[EVTLOG_SIGNATURE_SIZE];
    uint8_t reserved[12];
    uint8_t container_ver_major;
    uint8_t container_ver_minor;
    uint8_t pcr_event_ver_major;
    uint8_t pcr_event_ver_minor;
    uint32_t size;
    uint32_t pcr_events_offset;
    uint32_t next_event_offset;
    struct tpm_pcr_event pcr_events[];
} __packed;

#define HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1 8

struct heap_event_log_pointer_element2_1 {
	uint64_t phys_addr;
	uint32_t allocated_event_cont_size;
	uint32_t first_record_offset;
	uint32_t next_record_offset;
};

struct tpmt_ha {
	uint16_t algorithm_id;	/* tpmi_alg_hash */
	uint8_t digest[];	/* digest value in */
};

struct tpml_digest_values {
	uint32_t count;			/* Count of TPMT_HA structures */
	struct tpmt_ha digests[5];	/* Array of TPMT_HA structures */
};

struct tcg_efi_spec_id_event_algorithm_size {
	uint16_t algorithm_id;
	uint16_t digest_size;
} __packed;

struct tcg_efi_spec_id_event {
	uint8_t signature[16]; /* ‘spec id event03’, 00 */
	/* 00 – pc client platform class */
	/* 01 – server platform class */
	uint32_t plat_class;
	uint8_t spec_versionminor;	/* 00 – minor of 2.00 */
	uint8_t spec_versionmajor;	/* 02 – major of 2.00 */
	uint8_t spec_errata;		/* 00 – errata of 2.00 */
	uint8_t uintn_size;		/* 01 for uint32; 02 for uint64 */
	uint32_t number_of_algorithms;	/* number of hashing algorithms used */
	struct tcg_efi_spec_id_event_algorithm_size digest_sizes[5];
	uint8_t vendor_info_size;
	uint8_t vendor_info[];		/* vendor specific */
} __packed;

struct tcg_pcr_event2 {
	uint32_t pcr_index;
	uint32_t event_type;
	struct tpml_digest_values digest;
	uint32_t event_size;
	uint8_t event[];
} __packed;


