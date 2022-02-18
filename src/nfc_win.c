/*
 * Copyright (c) 2022 Micro Focus or one of its affiliates.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <winscard.h>

#include "fido.h"
#include "fido/param.h"
#include "iso7816.h"

static const uint8_t select_apdu[] = {
	0x00, 0xa4, 0x04, 0x00, 0x08, 0xA0, 0x00,
	0x00, 0x06 ,0x47, 0x2F, 0x00, 0x01, 0x00,
};
static const uint8_t v_u2f[] = { 'U', '2', 'F', '_', 'V', '2' };
static const uint8_t v_fido[] = { 'F', 'I', 'D', 'O', '_', '2', '_', '0' };
static const char prefix[] = FIDO_NFC_PREFIX "//winscard:{";

struct nfc_win {
	SCARDCONTEXT        scard_ctx;
	SCARDHANDLE         scard_handle;
	SCARD_IO_REQUEST    scard_tx_pci;
	uint8_t             rx_buf[FIDO_MAXMSG];
	DWORD               rx_len;
};

static int
nfc_win_tx(fido_dev_t *dev, uint8_t cmd, const unsigned char *buf, size_t count)
{
	iso7816_apdu_t  *apdu = NULL;
	const uint8_t   *ptr;
	size_t          len;
	int             ok = -1;

	switch (cmd) {
	case CTAP_CMD_INIT: /* select */
		ptr = select_apdu;
		len = sizeof(select_apdu);
		break;
	case CTAP_CMD_CBOR: /* wrap cbor */
		if (count > UINT16_MAX || (apdu = iso7816_new(0x80, 0x10, 0x80,
		    (uint16_t)count)) == NULL ||
		    iso7816_add(apdu, buf, count) < 0) {
			fido_log_debug("%s: iso7816", __func__);
			goto fail;
		}
		ptr = iso7816_ptr(apdu);
		len = iso7816_len(apdu);
		break;
	case CTAP_CMD_MSG: /* already an apdu */
		ptr = buf;
		len = count;
		break;
	default:
		fido_log_debug("%s: cmd=0x%02X", __func__, cmd);
		goto fail;
	}

	if (dev->io.write(dev->io_handle, ptr, len) < 0) {
		fido_log_debug("%s: io.write()", __func__);
		goto fail;
	}

	ok = 0;
fail:
	iso7816_free(&apdu);

	return ok;
}

static int
nfc_win_rx_init(fido_dev_t *dev, unsigned char *buf, size_t count)
{
	fido_ctap_info_t    *attr = (fido_ctap_info_t *)buf;
	uint8_t             f[64];
	int                 n;

	if (count != sizeof(*attr)) {
		fido_log_debug("%s: count=%zu", __func__, count);
		return -1;
	}

	memset(attr, 0, sizeof(*attr));

	if ((n = dev->io.read(dev->io_handle, f, sizeof(f), -1)) < 2 ||
	    (f[n - 2] << 8 | f[n - 1]) != SW_NO_ERROR) {
		fido_log_debug("%s: io.read()", __func__);
		return -1;
	}

	n -= 2;

	if (n == sizeof(v_u2f) && memcmp(f, v_u2f, sizeof(v_u2f)) == 0)
		attr->flags = FIDO_CAP_CBOR;
	else if (n == sizeof(v_fido) && memcmp(f, v_fido, sizeof(v_fido)) == 0)
		attr->flags = FIDO_CAP_CBOR | FIDO_CAP_NMSG;
	else {
		fido_log_debug("%s: unknown version string", __func__);
#ifdef FIDO_FUZZ
		attr->flags = FIDO_CAP_CBOR | FIDO_CAP_NMSG;
#else
		return -1;
#endif
	}

	memcpy(&attr->nonce, &dev->nonce, sizeof(attr->nonce)); /* XXX */

	return (int)count;
}

static int
nfc_win_rx_msg(fido_dev_t *dev, unsigned char *buf, size_t count)
{
	int n;

	if ((n = dev->io.read(dev->io_handle, buf, count, -1)) < 2) {
		fido_log_debug("%s: read", __func__);
		return -1;
	}

	return n;
}

static int
nfc_win_rx_cbor(fido_dev_t *dev, unsigned char *buf, size_t count)
{
	int n;

	if ((n = nfc_win_rx_msg(dev, buf, count)) < 2)
		return -1;

	return n - 2;
}

static int
nfc_win_rx(fido_dev_t *dev, uint8_t cmd, unsigned char *buf, size_t count)
{
	switch (cmd) {
	case CTAP_CMD_INIT:
		return nfc_win_rx_init(dev, buf, count);
	case CTAP_CMD_CBOR:
		return nfc_win_rx_cbor(dev, buf, count);
	case CTAP_CMD_MSG:
		return nfc_win_rx_msg(dev, buf, count);
	default:
		fido_log_debug("%s: cmd=%02x", __func__, cmd);
		return -1;
	}
}

static char *
nfc_win_strdup_n(const char *src, size_t len)
{
	char *dst;

	/* XXX pedro: fix len + 1 */
	if ((dst = malloc(len + 1)) != NULL) {
		memcpy(dst, src, len);
		dst[len] = 0;
	}

	return dst;
}

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
	if (is_fido(h, &req) < 0) {
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

static struct nfc_win *
nfc_win_new(SCARDCONTEXT scard_ctx, SCARDHANDLE scard_handle,
    SCARD_IO_REQUEST scard_tx_pci)
{
	struct nfc_win *ctx;

	if ((ctx = malloc(sizeof(*ctx))) == NULL) {
		fido_log_debug("%s: malloc", __func__);
		return NULL;
	}

	ctx->scard_ctx = scard_ctx;
	ctx->scard_handle = scard_handle;
	ctx->scard_tx_pci = scard_tx_pci;
	ctx->rx_len = 0;
	explicit_bzero(ctx->rx_buf, sizeof(ctx->rx_buf));

	return ctx;
}

static void
nfc_win_free(struct nfc_win **ctx_p)
{
	struct nfc_win *ctx;

	if (ctx_p == NULL || (ctx = *ctx_p) == NULL)
		return;
	if (ctx->scard_handle != 0)
		SCardDisconnect(ctx->scard_handle, SCARD_LEAVE_CARD);
	if (ctx->scard_ctx != 0)
		SCardReleaseContext(ctx->scard_ctx);

	explicit_bzero(ctx->rx_buf, sizeof(ctx->rx_buf));
	free(ctx);
	*ctx_p = NULL;
}


void *
fido_nfc_open(const char *path)
{
	struct nfc_win      *ctx = NULL;
	char                *reader = NULL;
	SCARDCONTEXT        scard_ctx = 0;
	SCARDHANDLE         scard_handle = 0;
	SCARD_IO_REQUEST    scard_tx_pci;
	DWORD               scard_active_protocol = 0;
	LONG                scard_r;

	if ((reader = get_reader(path)) == NULL) {
		fido_log_debug("%s: get_reader(%s)", __func__, path);
		goto fail;
	}

	scard_r = SCardEstablishContext(SCARD_SCOPE_SYSTEM, 0, 0, &scard_ctx);
	if (scard_r != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardEstablishContext(): 0x%08X", __func__,
		    scard_r);
		goto fail;
	}

	scard_r = SCardConnectA(scard_ctx, reader, SCARD_SHARE_SHARED,
	    SCARD_PROTOCOL_Tx, &scard_handle, &scard_active_protocol);
	if (scard_r != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardConnectA(%s) - 0x%08X", __func__, reader, scard_r);
		goto fail;
	}

	fido_log_debug("%s: scard_active_protocol: 0x%08X", __func__,
	    scard_active_protocol);

	switch (scard_active_protocol) {
	case SCARD_PROTOCOL_T0:
		scard_tx_pci.dwProtocol = SCARD_PCI_T0->dwProtocol;
		scard_tx_pci.cbPciLength = SCARD_PCI_T0->cbPciLength;
		break;
	case SCARD_PROTOCOL_T1:
		scard_tx_pci.dwProtocol = SCARD_PCI_T1->dwProtocol;
		scard_tx_pci.cbPciLength = SCARD_PCI_T1->cbPciLength;
		break;
	default:
		fido_log_debug("%s: unknown card protocol", __func__);
		goto fail;
	}

	if ((ctx = nfc_win_new(scard_ctx, scard_handle,
	    scard_tx_pci)) == NULL) {
		fido_log_debug("%s: nfc_win_new", __func__);
		goto fail;
	}

	return ctx;
fail:
	if (scard_handle != 0)
		SCardDisconnect(scard_handle, SCARD_LEAVE_CARD);
	if (scard_ctx != 0)
		SCardReleaseContext(scard_ctx);
	free(reader);

	return NULL;
}

static void
nfc_win_close(void *handle)
{
	struct nfc_win *ctx = handle;

	if (ctx->scard_handle != 0)
		SCardDisconnect(ctx->scard_handle, SCARD_LEAVE_CARD);
	if (ctx->scard_ctx != 0)
		SCardReleaseContext(ctx->scard_ctx);
	if (ctx->rx_len > 0)
		explicit_bzero(ctx->rx_buf, (size_t)ctx->rx_len);

	nfc_win_free(&ctx);
}

static int
nfc_win_read(void *handle, unsigned char *buf, size_t len)
{
	struct nfc_win *ctx = handle;
	size_t r;

	if (ctx->rx_len == 0) {
		fido_log_debug("%s: rx_len", __func__);
		return -1;
	}

	if (ctx->rx_len > len) {
		fido_log_debug("%s: rx_len", __func__);
		return -1;
	}

	memcpy(buf, ctx->rx_buf, ctx->rx_len);
	r = ctx->rx_len;
	explicit_bzero(ctx->rx_buf, (size_t)ctx->rx_len);
	ctx->rx_len = 0;

	return (int)r;
}

static int
nfc_win_write(void *handle, const unsigned char *buf, size_t len)
{
	struct nfc_win *ctx = handle;
	LONG scard_r;

	fido_log_xxd(buf, len, "%s", __func__);

	if (len > INT_MAX) {
		fido_log_debug("%s: len", __func__);
		return -1;
	}

	if (ctx->rx_len > 0)
		explicit_bzero(ctx->rx_buf, (size_t)ctx->rx_len);

	ctx->rx_len = sizeof(ctx->rx_buf);
	scard_r = SCardTransmit(ctx->scard_handle, &ctx->scard_tx_pci, buf,
	    (DWORD)len, NULL, ctx->rx_buf, &ctx->rx_len);
	if (scard_r != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardTransmit(): 0x%08X", __func__,
		    scard_r);
		ctx->rx_len = 0;
		return -1;
	}

	return (int)len;
}

void
fido_nfc_close(void *handle)
{
	nfc_win_close(handle);
}

int
fido_nfc_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	(void)ms;
	return nfc_win_read(handle, buf, len);
}

int
fido_nfc_write(void *handle, const unsigned char *buf, size_t len)
{
	return nfc_win_write(handle, buf, len);
}

int
fido_nfc_tx(fido_dev_t *dev, uint8_t cmd, const unsigned char *buf,
    size_t count)
{
	return nfc_win_tx(dev, cmd, buf, count);
}

int
fido_nfc_rx(fido_dev_t *dev, uint8_t cmd, unsigned char *buf, size_t count, int ms)
{
	(void)ms;
	return nfc_win_rx(dev, cmd, buf, count);
}
