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

#include <syscfg/syscfg.h>

#if MYNEWT_VAL(BLE_LL_CERT_MODE_ON) == 1

#include "assert.h"
#include "os/os.h"
#include "controller/ble_ll.h"
#include "controller/ble_phy.h"
#include "controller/ble_ll_sched.h"
#include "ble_ll_test_priv.h"

struct test_ctx {
    int active;
    struct os_mbuf *om;
    int chan;
    int phy_mode;
    uint16_t num_of_packets;
    struct ble_ll_sched_item sch;
    uint32_t itvl_ticks;
    uint32_t itvl_rem_usec;
    struct os_event evt;
};

static struct test_ctx g_ble_ll_test_ctx;

static const uint8_t g_ble_ll_test_prbs9_data[] = {
                0xff, 0xc1, 0xfb, 0xe8, 0x4c, 0x90, 0x72, 0x8b,
                0xe7, 0xb3, 0x51, 0x89, 0x63, 0xab, 0x23, 0x23,
                0x02, 0x84, 0x18, 0x72, 0xaa, 0x61, 0x2f, 0x3b,
                0x51, 0xa8, 0xe5, 0x37, 0x49, 0xfb, 0xc9, 0xca,
                0x0c, 0x18, 0x53, 0x2c, 0xfd, 0x45, 0xe3, 0x9a,
                0xe6, 0xf1, 0x5d, 0xb0, 0xb6, 0x1b, 0xb4, 0xbe,
                0x2a, 0x50, 0xea, 0xe9, 0x0e, 0x9c, 0x4b, 0x5e,
                0x57, 0x24, 0xcc, 0xa1, 0xb7, 0x59, 0xb8, 0x87,
                0xff, 0xe0, 0x7d, 0x74, 0x26, 0x48, 0xb9, 0xc5,
                0xf3, 0xd9, 0xa8, 0xc4, 0xb1, 0xd5, 0x91, 0x11,
                0x01, 0x42, 0x0c, 0x39, 0xd5, 0xb0, 0x97, 0x9d,
                0x28, 0xd4, 0xf2, 0x9b, 0xa4, 0xfd, 0x64, 0x65,
                0x06, 0x8c, 0x29, 0x96, 0xfe, 0xa2, 0x71, 0x4d,
                0xf3, 0xf8, 0x2e, 0x58, 0xdb, 0x0d, 0x5a, 0x5f,
                0x15, 0x28, 0xf5, 0x74, 0x07, 0xce, 0x25, 0xaf,
                0x2b, 0x12, 0xe6, 0xd0, 0xdb, 0x2c, 0xdc, 0xc3,
                0x7f, 0xf0, 0x3e, 0x3a, 0x13, 0xa4, 0xdc, 0xe2,
                0xf9, 0x6c, 0x54, 0xe2, 0xd8, 0xea, 0xc8, 0x88,
                0x00, 0x21, 0x86, 0x9c, 0x6a, 0xd8, 0xcb, 0x4e,
                0x14, 0x6a, 0xf9, 0x4d, 0xd2, 0x7e, 0xb2, 0x32,
                0x03, 0xc6, 0x14, 0x4b, 0x7f, 0xd1, 0xb8, 0xa6,
                0x79, 0x7c, 0x17, 0xac, 0xed, 0x06, 0xad, 0xaf,
                0x0a, 0x94, 0x7a, 0xba, 0x03, 0xe7, 0x92, 0xd7,
                0x15, 0x09, 0x73, 0xe8, 0x6d, 0x16, 0xee, 0xe1,
                0x3f, 0x78, 0x1f, 0x9d, 0x09, 0x52, 0x6e, 0xf1,
                0x7c, 0x36, 0x2a, 0x71, 0x6c, 0x75, 0x64, 0x44,
                0x80, 0x10, 0x43, 0x4e, 0x35, 0xec, 0x65, 0x27,
                0x0a, 0xb5, 0xfc, 0x26, 0x69, 0x3f, 0x59, 0x99,
                0x01, 0x63, 0x8a, 0xa5, 0xbf, 0x68, 0x5c, 0xd3,
                0x3c, 0xbe, 0x0b, 0xd6, 0x76, 0x83, 0xd6, 0x57,
                0x05, 0x4a, 0x3d, 0xdd, 0x81, 0x73, 0xc9, 0xeb,
                0x8a, 0x84, 0x39, 0xf4, 0x36, 0x0b, 0xf7 };

static const uint8_t g_ble_ll_test_prbs15_data[] = {
                0xff, 0x7f, 0xf0, 0x3e, 0x3a, 0x13, 0xa4, 0xdc,
                0xe2, 0xf9, 0x6c, 0x54, 0xe2, 0xd8, 0xea, 0xc8,
                0x88, 0x00, 0x21, 0x86, 0x9c, 0x6a, 0xd8, 0xcb,
                0x4e, 0x14, 0x6a, 0xf9, 0x4d, 0xd2, 0x7e, 0xb2,
                0x32, 0x03, 0xc6, 0x14, 0x4b, 0x7f, 0xd1, 0xb8,
                0xa6, 0x79, 0x7c, 0x17, 0xac, 0xed, 0x06, 0xad,
                0xaf, 0x0a, 0x94, 0x7a, 0xba, 0x03, 0xe7, 0x92,
                0xd7, 0x15, 0x09, 0x73, 0xe8, 0x6d, 0x16, 0xee,
                0xe1, 0x3f, 0x78, 0x1f, 0x9d, 0x09, 0x52, 0x6e,
                0xf1, 0x7c, 0x36, 0x2a, 0x71, 0x6c, 0x75, 0x64,
                0x44, 0x80, 0x10, 0x43, 0x4e, 0x35, 0xec, 0x65,
                0x27, 0x0a, 0xb5, 0xfc, 0x26, 0x69, 0x3f, 0x59,
                0x99, 0x01, 0x63, 0x8a, 0xa5, 0xbf, 0x68, 0x5c,
                0xd3, 0x3c, 0xbe, 0x0b, 0xd6, 0x76, 0x83, 0xd6,
                0x57, 0x05, 0x4a, 0x3d, 0xdd, 0x81, 0x73, 0xc9,
                0xeb, 0x8a, 0x84, 0x39, 0xf4, 0x36, 0x0b, 0xf7,
                0xf0, 0x1f, 0xbc, 0x8f, 0xce, 0x04, 0x29, 0xb7,
                0x78, 0x3e, 0x1b, 0x95, 0x38, 0xb6, 0x3a, 0x32,
                0x22, 0x40, 0x88, 0x21, 0xa7, 0x1a, 0xf6, 0xb2,
                0x13, 0x85, 0x5a, 0x7e, 0x93, 0xb4, 0x9f, 0xac,
                0xcc, 0x80, 0x31, 0xc5, 0xd2, 0x5f, 0x34, 0xae,
                0x69, 0x1e, 0xdf, 0x05, 0x6b, 0xbb, 0x41, 0xeb,
                0xab, 0x02, 0xa5, 0x9e, 0xee, 0xc0, 0xb9, 0xe4,
                0x75, 0x45, 0xc2, 0x1c, 0x7a, 0x9b, 0x85, 0x7b,
                0xf8, 0x0f, 0xde, 0x47, 0x67, 0x82, 0x94, 0x5b,
                0x3c, 0x9f, 0x8d, 0x4a, 0x1c, 0x5b, 0x1d, 0x19,
                0x11, 0x20, 0xc4, 0x90, 0x53, 0x0d, 0x7b, 0xd9,
                0x89, 0x42, 0x2d, 0xbf, 0x49, 0xda, 0x4f, 0x56,
                0x66, 0xc0, 0x98, 0x62, 0xe9, 0x2f, 0x1a, 0xd7,
                0x34, 0x8f, 0xef, 0x82, 0xb5, 0xdd, 0xa0, 0xf5,
                0x55, 0x81, 0x52, 0x4f, 0x77, 0xe0, 0x5c, 0xf2,
                0xba, 0x22, 0x61, 0x0e, 0xbd, 0xcd, 0xc2 };

static uint32_t g_ble_ll_test_sync_word = 0x71764129;
static uint32_t g_ble_ll_test_crc = 0x555555;

static void
ble_ll_test_set_next_tx(struct test_ctx *ctx)
{
    struct ble_ll_sched_item *sch = &ctx->sch;

    sch->start_time += ctx->itvl_ticks;
    sch->remainder += ctx->itvl_rem_usec;
    if (sch->remainder > 30) {
       sch->start_time++;
       sch->remainder -= 30;
    }

    sch->start_time -= g_ble_ll_sched_offset_ticks;
}

static void
ble_ll_test_event(struct os_event *evt) {
    /* It is called in LL context */
    struct test_ctx *c = evt->ev_arg;
    int rc;

    if (!c->om) {
        return;
    }

    ble_ll_test_set_next_tx(c);
    rc = ble_ll_sched_tx_test(&c->sch);
    assert(rc == 0);
}

static void
ble_ll_tx_test_done (void *arg)
{
    os_sr_t sr;
    struct test_ctx *c;

    OS_ENTER_CRITICAL(sr);
    c = arg;
    if (!c->evt.ev_cb) {
        OS_EXIT_CRITICAL(sr);
        return;
    }
    c->num_of_packets++;
    /* Reschedule event in LL context */
    os_eventq_put(&g_ble_ll_data.ll_evq, &c->evt);
    OS_EXIT_CRITICAL(sr);

    ble_ll_state_set(BLE_LL_STATE_STANDBY);
}

static int
ble_ll_test_tx_test_cb(struct ble_ll_sched_item *sch)
{
    struct test_ctx *ctx = sch->cb_arg;
    int rc;

    if (!ctx->active) {
        return BLE_LL_SCHED_STATE_DONE;
    }

    ble_ll_state_set(BLE_LL_STATE_TEST_MODE);

    rc = ble_phy_setchan(ctx->chan, g_ble_ll_test_sync_word, g_ble_ll_test_crc);
    if (rc != 0) {
        assert(0);
        return BLE_LL_SCHED_STATE_DONE;
    }

    ble_phy_mode_set(ctx->phy_mode, ctx->phy_mode);
    sch->start_time += g_ble_ll_sched_offset_ticks;

    rc = ble_phy_tx_set_start_time(sch->start_time, sch->remainder);
    if (rc != 0) {
        assert(0);
        return BLE_LL_SCHED_STATE_DONE;
    }

    ble_phy_set_txend_cb(ble_ll_tx_test_done, ctx);

    rc = ble_phy_tx(ctx->om, BLE_PHY_TRANSITION_NONE);
    assert(rc == 0);

    return BLE_LL_SCHED_STATE_DONE;
}

static void
ble_ll_test_calculate_itvl(struct test_ctx *ctx, uint8_t len, int phy_mode)
{
    uint32_t l;
    uint32_t itvl_usec;
    uint32_t itvl_ticks;

    /* Calculate interval */
    l = ble_ll_pdu_tx_time_get(len, phy_mode);
    itvl_usec = ((l + 249 + 624) / 625) * 625;

    itvl_ticks = os_cputime_usecs_to_ticks(itvl_usec);
    ctx->itvl_rem_usec = (uint8_t)(itvl_usec -
                                        os_cputime_ticks_to_usecs(itvl_ticks));
    if (ctx->itvl_rem_usec == 31) {
        ctx->itvl_rem_usec = 0;
        ++itvl_ticks;
    }
    ctx->itvl_ticks = itvl_ticks;
}

static int
ble_ll_create_tx_test_ctx(uint8_t packet_payload, uint8_t len, int chan,
                          int phy_mode)
{
    int i;
    int rc;
    uint8_t byte_pattern;
    struct ble_ll_sched_item *s = &g_ble_ll_test_ctx.sch;
    struct ble_mbuf_hdr *ble_hdr;

    g_ble_ll_test_ctx.om = os_msys_get_pkthdr(len, sizeof(struct ble_mbuf_hdr));
    assert(g_ble_ll_test_ctx.om);

    g_ble_ll_test_ctx.phy_mode = phy_mode;
    g_ble_ll_test_ctx.chan = chan;

    switch(packet_payload) {
    case 0x00:
        rc = os_mbuf_append(g_ble_ll_test_ctx.om,
                            &g_ble_ll_test_prbs9_data, len);
        assert(rc != 0);
        goto schedule;
    case 0x01:
        byte_pattern = 0x0F;
        break;
    case 0x02:
        byte_pattern = 0x55;
        break;
    case 0x03:
        rc = os_mbuf_append(g_ble_ll_test_ctx.om,
                              &g_ble_ll_test_prbs15_data, len);
        assert(rc != 0);
        goto schedule;
    case 0x04:
        byte_pattern = 0xFF;
        break;
    case 0x05:
        byte_pattern = 0x00;
        break;
    case 0x06:
        byte_pattern = 0xF0;
        break;
    case 0x07:
        byte_pattern = 0xAA;
        break;
    default:
        return 1;
    }

    for (i = 0; i < len; i++) {
        if (os_mbuf_append(g_ble_ll_test_ctx.om, &byte_pattern, 1)) {
            return 1;
        }
    }

schedule:

    ble_hdr = BLE_MBUF_HDR_PTR(g_ble_ll_test_ctx.om);
    ble_hdr->txinfo.offset = 0;
    ble_hdr->txinfo.flags = 0;
    ble_hdr->txinfo.pyld_len = len;
    ble_hdr->txinfo.hdr_byte = packet_payload;

    s->sched_cb = ble_ll_test_tx_test_cb;
    s->cb_arg = &g_ble_ll_test_ctx;
    s->sched_type = BLE_LL_SCHED_TYPE_CERT_TEST;
    s->start_time =  os_cputime_get32() +
                                       os_cputime_usecs_to_ticks(5000);

    /* Prepare os_event */
    g_ble_ll_test_ctx.evt.ev_cb = ble_ll_test_event;
    g_ble_ll_test_ctx.evt.ev_arg = &g_ble_ll_test_ctx;

    ble_ll_test_calculate_itvl(&g_ble_ll_test_ctx, len, phy_mode);

    /* Set some start point for TX packets */
    rc = ble_ll_sched_tx_test(s);
    assert(rc == 0);

    g_ble_ll_test_sync_word = BLE_ACCESS_ADDR_ADV;//ble_ll_conn_calc_access_addr();
    g_ble_ll_test_ctx.active = 1;
    return 0;
}

static void
ble_ll_test_ctx_free(struct test_ctx * ctx)
{
    os_sr_t sr;

    OS_ENTER_CRITICAL(sr);

    ble_phy_disable();
    ble_ll_state_set(BLE_LL_STATE_STANDBY);

    ble_ll_sched_rmv_elem(&ctx->sch);
    os_mbuf_free_chain(ctx->om);
    ctx->om = NULL;
    ctx->active = 0;
    OS_EXIT_CRITICAL(sr);

}

int
ble_ll_test_tx_test(uint8_t *cmdbuf)
{
    uint8_t tx_chan = cmdbuf[0];
    uint8_t len = cmdbuf[1];
    uint8_t packet_payload = cmdbuf[2];

    if (tx_chan > 0x27 || packet_payload > 0x07) {
        return BLE_ERR_INV_HCI_CMD_PARMS;
    }

    if (ble_ll_create_tx_test_ctx(packet_payload, len, tx_chan, BLE_PHY_MODE_1M)) {
        return BLE_ERR_UNSPECIFIED;
    }

    return BLE_ERR_SUCCESS;
}

int ble_ll_test_rx_test(uint8_t *cmdbuf)
{
    //uint8_t rx_chan = cmdbuf[0];


    return 0;
}

int ble_ll_test_end_test(uint8_t *cmdbuf, uint8_t *rsp, uint8_t *rsplen)
{
    put_le16(rsp, g_ble_ll_test_ctx. num_of_packets);
    *rsplen = 2;
    ble_ll_test_ctx_free(&g_ble_ll_test_ctx);
    return BLE_ERR_SUCCESS;
}

int ble_ll_test_enh_rx_test(uint8_t *cmdbuf)
{
    return 0;
}

int ble_ll_test_enh_tx_test(uint8_t *cmdbuf)
{
    return 0;
}

#endif
