/* SPDX-License-Identifier: MIT */
/*
 * Botlink Result Types
 * Convenience aliases for datapod Result types
 */

#pragma once

#include <datapod/datapod.hpp>

namespace botlink {

    using namespace dp;

    // =============================================================================
    // Result Type Aliases
    // =============================================================================

    // Generic result with custom error type
    template <typename T, typename E = Error> using Result = dp::Result<T, E>;

    // Result with default Error type
    template <typename T> using Res = dp::Res<T>;

    // Void result (operations that don't return a value)
    using VoidRes = dp::VoidRes;

    // =============================================================================
    // Result Factory Functions
    // =============================================================================

    namespace result {

        using dp::result::err;
        using dp::result::Err;
        using dp::result::ok;
        using dp::result::Ok;

    } // namespace result

    // =============================================================================
    // Error Creation Helpers
    // =============================================================================

    namespace err {

        inline auto io(const char *msg) -> Error { return Error::io_error(msg); }

        inline auto invalid(const char *msg) -> Error { return Error::invalid_argument(msg); }

        inline auto not_found(const char *msg) -> Error { return Error::not_found(msg); }

        inline auto permission(const char *msg) -> Error { return Error::permission_denied(msg); }

        inline auto timeout(const char *msg) -> Error { return Error::timeout(msg); }

        inline auto crypto(const char *msg) -> Error { return Error::io_error(msg); }

        inline auto network(const char *msg) -> Error { return Error::io_error(msg); }

        inline auto trust(const char *msg) -> Error { return Error::permission_denied(msg); }

        inline auto config(const char *msg) -> Error { return Error::invalid_argument(msg); }

    } // namespace err

    // =============================================================================
    // Serialization Helpers (using datapod directly)
    // =============================================================================

    namespace serial {

        // Deserialize from dp::Vector<u8> directly
        template <typename T> [[nodiscard]] inline auto deserialize(const Vector<u8> &data) -> Res<T> {
            try {
                auto result = dp::deserialize<dp::Mode::WITH_VERSION, T>(data.data(), data.size());
                return result::ok(std::move(result));
            } catch (const std::exception &e) {
                return result::err(err::invalid(e.what()));
            }
        }

        // Deserialize with offset (skip first N bytes)
        template <typename T> [[nodiscard]] inline auto deserialize(const Vector<u8> &data, usize offset) -> Res<T> {
            if (offset >= data.size()) {
                return result::err(err::invalid("Offset exceeds data size"));
            }
            try {
                auto result = dp::deserialize<dp::Mode::WITH_VERSION, T>(data.data() + offset, data.size() - offset);
                return result::ok(std::move(result));
            } catch (const std::exception &e) {
                return result::err(err::invalid(e.what()));
            }
        }

        // Serialize to dp::Vector<u8>
        template <typename T> [[nodiscard]] inline auto serialize(T &value) -> Vector<u8> {
            auto buf = dp::serialize<dp::Mode::WITH_VERSION>(value);
            Vector<u8> result;
            result.reserve(buf.size());
            for (const auto &b : buf) {
                result.push_back(b);
            }
            return result;
        }

    } // namespace serial

} // namespace botlink
