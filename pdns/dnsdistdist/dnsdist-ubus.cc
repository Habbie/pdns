/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "ext/json11/json11.hpp"

#include "dolog.hh"
#include "dnsdist.hh"
#include "dnsdist-ubus.hh"
#include "threadname.hh"

#include <libubus.h>

bool g_ubusEnabled{false};

static struct blob_buf b;

enum {
  CALL_CMD,
  __CALL_MAX
};

static const struct blobmsg_policy ubus_dnsdist_call_policy[] = {
  [CALL_CMD] = { .name = "cmd", .type = BLOBMSG_TYPE_STRING }
};

static int ubus_dnsdist_call(struct ubus_context *ctx, struct ubus_object *obj,
          struct ubus_request_data *req, const char *method,
          struct blob_attr *msg)
{
  struct blob_attr *data[__CALL_MAX];

  blobmsg_parse(ubus_dnsdist_call_policy, __CALL_MAX, data, blob_data(msg), blob_len(msg));
  if (!data[CALL_CMD]) {
    return UBUS_STATUS_INVALID_ARGUMENT;
  }

  std::string cmd(blobmsg_get_string(data[CALL_CMD]));

  cerr<<"got cmd="<<cmd<<endl;


  g_outputBuffer.clear();
  // FIXME: handle exceptions so an error does not kill the whole thread
  auto ret=g_lua.executeCode<
            boost::optional<
              boost::variant<
                string, 
                shared_ptr<DownstreamState>,
                ClientState*,
                std::unordered_map<string, double>
                >
              >
            >("return "+cmd);


  // FIXME: handle other return types without making a third copy of that code from dnsdist-console.cc
  // const auto strValue = boost::get<string>(&*ret);

  blob_buf_init(&b, 0);
  blobmsg_add_string(&b, "result", g_outputBuffer.c_str()); // FIXME: we threw ret away

  ubus_send_reply(ctx, req, b.head);

  return 0;
}

static const struct ubus_method ubus_dnsdist_methods[] = {
  UBUS_METHOD("call", ubus_dnsdist_call, ubus_dnsdist_call_policy)
};


// this code triggers ""error: designator order for field ‘ubus_object_type::methods’ does not match declaration order in ‘ubus_object_type’""
// because of https://github.com/cplusplus/draft/commit/2442418d5c3949a81d540284f8ccec5d0d24ac5f
// should probably fix that upstream in libubus.h
// static struct ubus_object_type ubus_dnsdist_object_type =
//   UBUS_OBJECT_TYPE("dnsdist", ubus_dnsdist_methods);

// so we do it by hand instead
static struct ubus_object_type ubus_dnsdist_object_type = {
  .name = "dnsdist",
  .id = 0,
  .methods = ubus_dnsdist_methods,
  .n_methods = __CALL_MAX
};

static struct ubus_object ubus_dnsdist_object = {
  .name = "dnsdist",
  .type = &ubus_dnsdist_object_type,
  .methods = ubus_dnsdist_methods,
  .n_methods = ARRAY_SIZE(ubus_dnsdist_methods)
};

void ubusThread(const std::string &socket)
{
  try
  {
    setThreadName("dnsdist/ubus");

    struct ubus_context *ubus = nullptr;

    ubus = ubus_connect(socket.c_str());
    if (ubus == nullptr) {
      throw std::runtime_error("could not connect to ubus");
    }

    auto ret = ubus_add_object(ubus, &ubus_dnsdist_object);
    if (ret) {
      throw std::runtime_error(std::string("failed to register ubus dnsdist object: ") + ubus_strerror(ret));
    }

    while(true) {
      sleep(1); // FIXME: poll the right FD instead, or use uloop
      ubus_handle_event(ubus);
    }
  }
  catch (const std::exception& e)
  {
    errlog("ubus thread died: %s", e.what());
  }
}  

