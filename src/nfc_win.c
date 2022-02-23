/*
 * Copyright (c) 2022 Micro Focus or one of its affiliates.
 * Copyright (c) 2022 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <winscard.h>

#include "fido.h"
#include "fido/param.h"
#include "iso7816.h"

static const uint8_t select_apdu[] = {
	0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00,
	0x00, 0x06 ,0x47, 0x2f, 0x00, 0x01, 0x00,
};
static const uint8_t v_u2f[] = { 'U', '2', 'F', '_', 'V', '2' };
static const uint8_t v_fido[] = { 'F', 'I', 'D', 'O', '_', '2', '_', '0' };
static const char prefix[] = FIDO_NFC_PREFIX "//winscard:{";

struct nfc_win {
	SCARDCONTEXT     ctx;
	SCARDHANDLE      h;
	SCARD_IO_REQUEST req;
	uint8_t          rx_buf[FIDO_MAXMSG];
	size_t           rx_len;
};

static char *
get_reader(const char *path)
{
	char *o = NULL, *p;
	char *reader = NULL;

	if (path == NULL)
		goto out;
	if ((o = p = strdup(path)) == NULL ||
	    strncmp(p, prefix, strlen(prefix)) != 0)
		goto out;
	p += strlen(prefix);
	if (strlen(p) == 0 || p[strlen(p) - 1] != '}')
		goto out;
	p[strlen(p) - 1] = '\0';
	reader = strdup(p);
out:
	free(o);

	return reader;
}

static int
prepare_io_request(DWORD prot, SCARD_IO_REQUEST *req)
{
	switch (prot) {
	case SCARD_PROTOCOL_T0:
		req->dwProtocol = SCARD_PCI_T0->dwProtocol;
		req->cbPciLength = SCARD_PCI_T0->cbPciLength;
		break;
	case SCARD_PROTOCOL_T1:
		req->dwProtocol = SCARD_PCI_T1->dwProtocol;
		req->cbPciLength = SCARD_PCI_T1->cbPciLength;
		break;
	default:
		fido_log_debug("%s: unknown protocol %u", __func__, prot);
		return -1;
	}

	return 0;
}

static bool
is_fido(SCARDHANDLE h, const SCARD_IO_REQUEST *req)
{
	unsigned char buf[64];
	DWORD len;
	LONG s;

	len = sizeof(buf);
	if ((s = SCardTransmit(h, req, select_apdu, (DWORD)sizeof(select_apdu),
	    NULL, buf, &len)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardTransmit 0x%lx", __func__, s);
		return false;
	}
	if (len < 2 || ((buf[len - 2] << 8) | buf[len - 1]) != SW_NO_ERROR) {
		fido_log_debug("%s: len %zu", __func__, (size_t)len);
		return false;
	}
	len -= 2;
	if (len == sizeof(v_u2f) && memcmp(buf, v_u2f, len) == 0) {
		fido_log_debug("%s: u2f", __func__);
		return true;
	}
	if (len == sizeof(v_fido) && memcmp(buf, v_fido, len) == 0) {
		fido_log_debug("%s: fido2", __func__);
		return true;
	}

	return false;
}

static char *
getattr(SCARDCONTEXT ctx, SCARDHANDLE h, DWORD attr)
{
	char *buf = NULL, *ret;
	DWORD len = SCARD_AUTOALLOCATE;
	LONG s;

	if ((s = SCardGetAttrib(h, attr, (void *)&buf,
	    &len)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardGetAttrib 0x%lx", __func__, s);
		return NULL;
	}
	ret = strndup(buf, len);
	SCardFreeMemory(ctx, buf);

	return ret;
}

static int
copy_info(fido_dev_info_t *di, SCARDCONTEXT ctx, const char *reader)
{
	SCARDHANDLE h = 0;
	SCARD_IO_REQUEST req;
	DWORD prot = 0;
	LONG s;
	char path[512];
	int r, ok = -1;

	memset(di, 0, sizeof(*di));
	memset(&req, 0, sizeof(req));

	if ((s = SCardConnectA(ctx, reader, SCARD_SHARE_SHARED,
	    SCARD_PROTOCOL_Tx, &h, &prot)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardConnectA 0x%x", __func__, s);
		goto fail;
	}
	if (prepare_io_request(prot, &req) < 0) {
		fido_log_debug("%s: prepare_io_request", __func__);
		goto fail;
	}
	if (is_fido(h, &req) == false) {
		fido_log_debug("%s: skipping %s", __func__, reader);
		goto fail;
	}
	if ((r = snprintf(path, sizeof(path), "%s//winscard:{%s}",
	    FIDO_NFC_PREFIX, reader)) < 0 || (size_t)r >= sizeof(path)) {
		fido_log_debug("%s: snprintf", __func__);
		goto fail;
	}
	di->path = strdup(path);
	if ((di->manufacturer = getattr(ctx, h,
	    SCARD_ATTR_VENDOR_NAME)) == NULL)
		di->manufacturer = strdup("");
	if ((di->product = getattr(ctx, h,
	    SCARD_ATTR_DEVICE_FRIENDLY_NAME)) == NULL)
		di->product = strdup("");
	if (di->path == NULL || di->manufacturer == NULL || di->product == NULL)
		goto fail;

	ok = 0;
fail:
	if (h != 0)
		SCardDisconnect(h, SCARD_LEAVE_CARD);
	if (ok < 0) {
		free(di->path);
		free(di->manufacturer);
		free(di->product);
		explicit_bzero(di, sizeof(*di));
	}

	return ok;
}

int
fido_nfc_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
	SCARDCONTEXT ctx = 0;
	const char *buf = NULL, *reader;
	DWORD len;
	LONG s;
	int r = FIDO_ERR_INTERNAL;

	*olen = 0;

	if (ilen == 0)
		return FIDO_OK;
	if (devlist == NULL)
		return FIDO_ERR_INVALID_ARGUMENT;

	if ((s = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
	    &ctx)) != SCARD_S_SUCCESS || ctx == 0) {
		fido_log_debug("%s: SCardEstablishContext 0x%lx", __func__, s);
		if (s == SCARD_E_NO_SERVICE || s == SCARD_E_NO_SMARTCARD)
			r = FIDO_OK; /* suppress error */
		goto out;
	}

	len = SCARD_AUTOALLOCATE;
	if ((s = SCardListReadersA(ctx, NULL, (void *)&buf,
	    &len)) != SCARD_S_SUCCESS || buf == NULL) {
		fido_log_debug("%s: SCardListReadersA 0x%lx", __func__, s);
		if (s == SCARD_E_NO_READERS_AVAILABLE)
			r = FIDO_OK; /* suppress error */
		goto out;
	}
	/* sanity check "multi-string" */
	if (len < 2 || buf[len - 1] != 0 || buf[len - 2] != '\0') {
		fido_log_debug("%s: can't parse buf returned by "
		    "SCardListReadersA", __func__);
		goto out;
	}

	for (reader = buf; *reader != 0; reader += strlen(reader) + 1) {
		if (copy_info(&devlist[*olen], ctx, reader) == 0) {
			devlist[*olen].io = (fido_dev_io_t) {
				fido_nfc_open,
				fido_nfc_close,
				fido_nfc_read,
				fido_nfc_write,
			};
			devlist[*olen].transport = (fido_dev_transport_t) {
				fido_nfc_rx,
				fido_nfc_tx,
			};
			if (++(*olen) == ilen)
				break;
		}
	}

	r = FIDO_OK;
out:
	if (buf != NULL)
		SCardFreeMemory(ctx, buf);
	if (ctx != 0)
		SCardReleaseContext(ctx);

	return r;
}

void *
fido_nfc_open(const char *path)
{
	char *reader;
	struct nfc_win *dev = NULL;
	SCARDCONTEXT ctx = 0;
	SCARDHANDLE h = 0;
	SCARD_IO_REQUEST req;
	DWORD prot = 0;
	LONG s;

	memset(&req, 0, sizeof(req));

	if ((reader = get_reader(path)) == NULL) {
		fido_log_debug("%s: get_reader(%s)", __func__, path);
		goto fail;
	}
	if ((s = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
	    &ctx)) != SCARD_S_SUCCESS || ctx == 0) {
		fido_log_debug("%s: SCardEstablishContext 0x%lx", __func__, s);
		goto fail;

	}
	if ((s = SCardConnectA(ctx, reader, SCARD_SHARE_SHARED,
	    SCARD_PROTOCOL_Tx, &h, &prot)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardConnectA 0x%x", __func__, s);
		goto fail;
	}
	if (prepare_io_request(prot, &req) < 0) {
		fido_log_debug("%s: prepare_io_request", __func__);
		goto fail;
	}
	if ((dev = calloc(1, sizeof(*dev))) == NULL)
		goto fail;

	dev->ctx = ctx;
	dev->h = h;
	dev->req = req;
	ctx = 0;
	h = 0;
fail:
	if (h != 0)
		SCardDisconnect(h, SCARD_LEAVE_CARD);
	if (ctx != 0)
		SCardReleaseContext(ctx);
	free(reader);

	return dev;
}

void
fido_nfc_close(void *handle)
{
	struct nfc_win *dev = handle;

	if (dev->h != 0)
		SCardDisconnect(dev->h, SCARD_LEAVE_CARD);
	if (dev->ctx != 0)
		SCardReleaseContext(dev->ctx);

	explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
	free(dev);
}

int
fido_nfc_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	struct nfc_win *dev = handle;
	int r;

	(void)ms;
	if (dev->rx_len == 0) {
		fido_log_debug("%s: dev->rx_len == 0", __func__);
		return -1;
	}
	if (dev->rx_len > INT_MAX) {
		fido_log_debug("%s: dev->rx_len > INT_MAX", __func__);
		return -1;
	}
	if (dev->rx_len > len) {
		fido_log_debug("%s: %zu > %zu", __func__, dev->rx_len, len);
		return -1;
	}
	memcpy(buf, dev->rx_buf, dev->rx_len);
	explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
	r = (int)dev->rx_len;
	dev->rx_len = 0;

	return r;
}

int
fido_nfc_write(void *handle, const unsigned char *buf, size_t len)
{
	struct nfc_win *dev = handle;
	DWORD n;
	LONG s;

	if (len > INT_MAX) {
		fido_log_debug("%s: len", __func__);
		return -1;
	}
	if (dev->rx_len) {
		fido_log_xxd(dev->rx_buf, dev->rx_len, "%s: dropping %zu bytes "
		    "from input buffer", __func__, dev->rx_len);
	}
	explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
	dev->rx_len = 0;
	n = (DWORD)sizeof(dev->rx_buf);
	if ((s = SCardTransmit(dev->h, &dev->req, buf, (DWORD)len, NULL,
	    dev->rx_buf, &n)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardTransmit 0x%lx", __func__, s);
		explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
		return -1;
	}
	dev->rx_len = (size_t)n;
	fido_log_xxd(dev->rx_buf, dev->rx_len, "%s: read", __func__);
		
	return (int)len;
}
