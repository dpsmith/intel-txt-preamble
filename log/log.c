#include <string.h>

#include "log.h"

/* init_tpm12_log: initializes logging container structure and returns the
 *	size of what is stored in the heap element data field that is passed
 *	as the parameter.
 */
uint32_t init_tpm12_log(uint8_t *data)
{
	struct heap_tpm_event_log_element *elem;
	struct os_mle_data *mle_data = get_os_mle_data_start();
	struct event_log_container *log;

	elem = (struct heap_tpm_event_log_element *)data;
	elem->event_log_phys_addr =
		(uint64_t)(uintptr_t)mle_data->event_log_buffer;

	log = (struct event_log_container *)mle_data->event_log_buffer;

	memcpy((uint8_t *)log->signature, EVTLOG_SIGNATURE,
		EVTLOG_SIGNATURE_SIZE);

	log->container_ver_major = EVTLOG_CNTNR_MAJOR_VER;
	log->container_ver_minor = EVTLOG_CNTNR_MINOR_VER;
	log->pcr_event_ver_major = EVTLOG_EVT_MAJOR_VER;
	log->pcr_event_ver_minor = EVTLOG_EVT_MINOR_VER;
	log->size = EVTLOG_CNTNR_SIZE;
	/* The offsets are relative to beginning of the log container with the
	 * PCR events beginning just after next_event_offset */
	log->pcr_events_offset = EVTLOG_CNTNR_SIZE;
	log->next_event_offset = EVTLOG_CNTNR_SIZE;

	return sizeof(struct heap_tpm_event_log_element);
}

/* Using tcg_pcr_event2 as a universial event container */
uint32_t tpm12_log_append(struct tcg_pcr_event2 *e)
{
	struct tcg_pcr_event *event;
	struct os_mle_data *mle_data = get_os_mle_data_start();
	struct event_log_container *log;
	/* tcg_pcr_event static fields are 32 bytes */
	uint32_t event_size = e->event_size + 32;

	if ((e->event_type != EVTYPE_PCRMAPPING) &&
	    (e->digest.count != 1) &&
	    (e->digest.digests[0].algorithm_id != TPM_ALG_SHA1)) {
		/* passed a bad hash */
		return 0;
	}

	log = (struct event_log_container *)mle_data->event_log_buffer;

	if (event_size > MAX_PCR_EVENT_SIZE)
		event_size = 32;

	if ((log->size + event_size) > mle_data->event_log_size) {
		/* not enough space left in the log */
		return 0;
	}

	event = (struct tcg_pcr_event *)((uintptr_t)log +
		log->next_event_offset);

        event->pcr_index = e->pcr_index;
        event->type = e->event_type;
	event->size = 0;
        memcpy(event->digest, e->digest.digests[0].digest, 20);
	if (event_size > 32) {
		event->size = e->event_size;
		memcpy(event->data, e->event, e->event_size);
	}

	log->size += event_size;
	log->next_event_offset += event_size;

	return event_size;
}

uint32_t init_tpm20_log(uint8_t *data)
{
	struct heap_event_log_pointer_element2_1 *elem;
	struct os_mle_data *mle_data = get_os_mle_data_start();

	elem = (struct heap_event_log_pointer_element2_1 *)data;
	elem->phys_addr = (uint64_t)(uintptr_t)mle_data->event_log_buffer;
	elem->allocated_event_cont_size = MAX_EVENT_LOG_SIZE;
	elem->first_record_offset = 0;
	elem->next_record_offset = 0;

	return sizeof(struct heap_event_log_pointer_element2_1);
}

struct heap_ext_data_element *get_heap_event_log_elem()
{
	struct os_sinit_data *sinit_data = get_os_sinit_data_start();
	struct heap_ext_data_element *elem = sinit_data->ext_data_elts;

	do {
		if (elem->type == HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR)
			break;

		if (elem->type == HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1)
			break;

		elem = (struct heap_ext_data_element *)
			((uintptr_t)elem + elem->size);
	} while (elem->type != HEAP_EXTDATA_TYPE_END);

	if (elem->type == HEAP_EXTDATA_TYPE_END)
		return NULL;
	else
		return elem;
}

uint32_t tpml_digest_size(struct tpml_digest_values *tpml)
{
	uint32_t count=0, size=4;

	while (count < tpml->count) {
		size += 2;
		switch (tpml->digests[count].algorithm_id) {
		case TPM_ALG_SHA1:
			size += 20;
			break;
		case TPM_ALG_SHA256:
			size += 32;
			break;
		case TPM_ALG_SHA384:
			size += 48;
			break;
		case TPM_ALG_SHA512:
			size += 64;
			break;
		case TPM_ALG_SM3_256:
			size += 32;
			break;
		}
	}

	return size;
}

uint32_t tpm20_log_append(struct tcg_pcr_event2 *e)
{
	struct os_mle_data *mle_data = get_os_mle_data_start();
	struct heap_ext_data_element *elem =
		get_heap_event_log_elem();
	struct heap_event_log_pointer_element2_1 *log =
		(struct heap_event_log_pointer_element2_1 *)elem->data;
	uint8_t *next_ptr;
	uint32_t event_size = 8;

	event_size += tpml_digest_size(&e->digest);
	event_size += 4 + e->event_size;

	if ((log->next_record_offset + event_size) >
	    log->allocated_event_cont_size) {
		event_size -= e->event_size;
		if ((log->next_record_offset + event_size) >
		    log->allocated_event_cont_size)
			return 0;

		e->event_size = 0;
	}

	if ((event_size > MAX_PCR_EVENT_SIZE) && (e->event_size != 0)) {
		event_size -= e->event_size;
		e->event_size = 0;
	}

	next_ptr = (uint8_t *)((uintptr_t)log->phys_addr +
		log->next_record_offset);
	log->next_record_offset += event_size;
	memcpy(next_ptr, (uint8_t *)e, event_size);

	return event_size;
}

uint8_t add_log_ext_elem(struct heap_ext_data_element *entry, enum tpm_type t)
{
	switch (t) {
	case TPM_12: {
		entry->type = HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR;
		entry->size = init_tpm12_log(entry->data);
		break;
	}
	case TPM_20: {
		entry->type = HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1;
		entry->size = init_tpm20_log(entry->data);
		break;
	}
	default:
		return 0;
	}

	return 1;
}

uint32_t log_append(struct tcg_pcr_event2 *e)
{
	uint32_t size = 0;
	struct heap_ext_data_element *elem =
		get_heap_event_log_elem();

	switch (elem->type) {
	case HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR:
		size = tpm12_log_append(e);
		break;
	case HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1:
		size = tpm20_log_append(e);
		break;
	}

	return size;
}
