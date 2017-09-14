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

#include "mesh/glue.h"
#include "mesh/mesh.h"
#include "mesh/pts.h"
#include "os/os_mbuf.h"

#include "adv.h"
#include "mesh_priv.h"
#include "net.h"
#include "transport.h"


int
mesh_net_send_msg(u8_t ttl, u16_t src_addr, u16_t dst_addr)
{
    int rc;
    struct bt_mesh_msg_ctx ctx = {
        .net_idx = BT_MESH_KEY_ANY,
        .app_idx = BT_MESH_KEY_DEV,
        .addr = dst_addr,
        .recv_ttl = 0,
        .friend_cred = 0,
        .send_ttl = ttl,
    };

	/* Needed size: opcode (2 bytes) + msg + MIC */
	struct os_mbuf *msg = NET_BUF_SIMPLE(2 + 2 + 4);

//	console_printf("net_idx 0x%04x app_idx 0x%04x src 0x%04x len %u: %s\n",
//	       ctx->net_idx, ctx->app_idx, ctx->addr, msg->om_len,
//	       bt_hex(msg->om_data, msg->om_len));

//	bt_mesh_model_msg_init(msg, OP_RELAY_STATUS);
//	net_buf_simple_add_u8(msg, bt_mesh_relay_get());
//	net_buf_simple_add_u8(msg, bt_mesh_relay_retransmit_get());

	struct bt_mesh_net_tx tx = {
		.sub = bt_mesh_subnet_get(ctx.net_idx),
		.ctx = &ctx,
		.src = src_addr,
	};

	if (net_buf_simple_tailroom(msg) < 4) {
		BT_ERR("Not enough tailroom for TransMIC");
		return -1;
	}

	if (msg->om_len > BT_MESH_TX_SDU_MAX - 4) {
		BT_ERR("Too big message");
		return -1;
	}

	rc = bt_mesh_trans_send(&tx, msg, NULL, NULL);
	os_mbuf_free_chain(msg);
	return rc;
}
