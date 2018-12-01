/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Microsoft Corporation
 *
 * -=- Robust Distributed System Nucleus (rDSN) -=-
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distrib#ute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <dsn/tool-api/zlocks.h>
#include <dsn/tool-api/group_address.h>
#include <dsn/dist/replication/partition_resolver.h>
#include "dist/replication/client/partition_resolver_simple.h"

namespace dsn {
namespace replication {

template <typename T>
bool vector_equal(const std::vector<T> &a, const std::vector<T> &b)
{
    if (a.size() != b.size())
        return false;
    for (const T &item : a) {
        if (std::find(b.begin(), b.end(), item) == b.end())
            return false;
    }
    for (const T &item : b) {
        if (std::find(a.begin(), a.end(), item) == a.end())
            return false;
    }
    return true;
}

class partition_resolver_manager : public dsn::utils::singleton<partition_resolver_manager>
{
public:
    partition_resolver_ptr find_or_create(const char *cluster_name,
                                          const std::vector<rpc_address> &meta_list,
                                          const char *app_path)
    {
        dsn::zauto_lock l(_lock);
        std::map<std::string, partition_resolver_ptr> &app_map = _resolvers[cluster_name];
        partition_resolver_ptr &ptr = app_map[app_path];

        if (ptr == nullptr) {
            dsn::rpc_address meta_group;
            meta_group.assign_group(cluster_name);
            meta_group.group_address()->add_list(meta_list);
            ptr = new partition_resolver_simple(meta_group, app_path);
            return ptr;
        } else {
            dsn::rpc_address meta_group = ptr->get_meta_server();
            const std::vector<dsn::rpc_address> &existing_list =
                meta_group.group_address()->members();
            if (!vector_equal(meta_list, existing_list)) {
                derror("meta list not match for cluster(%s)", cluster_name);
                return nullptr;
            }
            return ptr;
        }
    }

private:
    dsn::zlock _lock;
    // cluster_name -> <app_path, resolver>
    std::map<std::string, std::map<std::string, partition_resolver_ptr>> _resolvers;
};

/*static*/
partition_resolver_ptr partition_resolver::get_resolver(const char *cluster_name,
                                                        const std::vector<rpc_address> &meta_list,
                                                        const char *app_path)
{
    return partition_resolver_manager::instance().find_or_create(cluster_name, meta_list, app_path);
}

DEFINE_TASK_CODE(LPC_RPC_DELAY_CALL, TASK_PRIORITY_COMMON, THREAD_POOL_DEFAULT)
void partition_resolver::call_task(const rpc_response_task_ptr &t)
{
    auto &hdr = *(t->get_request()->header);
    uint64_t deadline_ms = dsn_now_ms() + hdr.client.timeout_ms;

    rpc_response_handler old_callback;
    t->fetch_current_handler(old_callback);
    auto new_callback = [this, deadline_ms, oc = std::move(old_callback)](
                            dsn::error_code err, dsn::message_ex *req, dsn::message_ex *resp) {
        if (req->header->gpid.value() != 0 && err != ERR_OK && err != ERR_HANDLER_NOT_FOUND &&
            err != ERR_APP_NOT_EXIST && err != ERR_OPERATION_DISABLED) {

            on_access_failure(req->header->gpid.get_partition_index(), err);
            // still got time, retry
            uint64_t nms = dsn_now_ms();
            uint64_t gap = 8 << req->send_retry_count;
            if (gap > 1000)
                gap = 1000;
            if (nms + gap < deadline_ms) {
                req->send_retry_count++;
                req->header->client.timeout_ms = static_cast<int>(deadline_ms - nms - gap);

                rpc_response_task_ptr ctask =
                    dynamic_cast<rpc_response_task *>(task::get_current_task());
                partition_resolver *r = this;

                dassert(ctask != nullptr, "current task must be rpc_response_task");
                ctask->replace_callback(std::move(oc));
                dassert(ctask->set_retry(false),
                        "rpc_response_task set retry failed, state = %s",
                        enum_to_string(ctask->state()));

                // sleep gap milliseconds before retry
                tasking::enqueue(LPC_RPC_DELAY_CALL,
                                 nullptr,
                                 [r, ctask]() { r->call_task(ctask); },
                                 0,
                                 std::chrono::milliseconds(gap));
                return;
            } else {
                derror("service access failed (%s), no more time for further "
                       "tries, set error = ERR_TIMEOUT, trace_id = %016" PRIx64,
                       error_code(err).to_string(),
                       req->header->trace_id);
                err = ERR_TIMEOUT;
            }
        }

        if (oc)
            oc(err, req, resp);
    };
    t->replace_callback(std::move(new_callback));

    resolve(hdr.client.partition_hash,
            [t](resolve_result &&result) mutable {
                if (result.err != ERR_OK) {
                    t->enqueue(result.err, nullptr);
                    return;
                }

                // update gpid when necessary
                auto &hdr = *(t->get_request()->header);
                if (hdr.gpid.value() != result.pid.value()) {
                    dassert(hdr.gpid.value() == 0, "inconsistent gpid");
                    hdr.gpid = result.pid;

                    // update thread hash if not assigned by applications
                    if (hdr.client.thread_hash == 0) {
                        hdr.client.thread_hash = result.pid.thread_hash();
                    }
                }
                dsn_rpc_call(result.address, t.get());
            },
            hdr.client.timeout_ms);
}
} // namespace replication
} // namespace dsn
