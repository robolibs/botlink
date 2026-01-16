/* SPDX-License-Identifier: MIT */
/*
 * Botlink Result Tests
 * Tests for result types and error helpers
 */

#include <doctest/doctest.h>
#include <botlink/botlink.hpp>

// Use explicit namespace to avoid ambiguity with datapod
namespace bl = botlink;

TEST_SUITE("Result - Type Aliases") {

    TEST_CASE("Res<T> ok value") {
        bl::Res<bl::i32> res = bl::result::ok(42);
        CHECK(res.is_ok());
        CHECK(res.value() == 42);
    }

    TEST_CASE("Res<T> error value") {
        bl::Res<bl::i32> res = bl::result::err(bl::err::invalid("test error"));
        CHECK(res.is_err());
        CHECK_FALSE(res.is_ok());
    }

    TEST_CASE("VoidRes ok") {
        bl::VoidRes res = bl::result::ok();
        CHECK(res.is_ok());
    }

    TEST_CASE("VoidRes error") {
        bl::VoidRes res = bl::result::err(bl::err::io("io error"));
        CHECK(res.is_err());
    }

}

TEST_SUITE("Result - Error Helpers") {

    TEST_CASE("err::io creates error with code") {
        bl::Error e = bl::err::io("file read failed");
        CHECK(e.code == bl::Error::IO_ERROR);
        CHECK(e.is_err());
    }

    TEST_CASE("err::invalid creates invalid argument error") {
        bl::Error e = bl::err::invalid("bad input");
        CHECK(e.code == bl::Error::INVALID_ARGUMENT);
    }

    TEST_CASE("err::not_found creates not found error") {
        bl::Error e = bl::err::not_found("missing file");
        CHECK(e.code == bl::Error::NOT_FOUND);
    }

    TEST_CASE("err::permission creates permission denied error") {
        bl::Error e = bl::err::permission("access denied");
        CHECK(e.code == bl::Error::PERMISSION_DENIED);
    }

    TEST_CASE("err::timeout creates timeout error") {
        bl::Error e = bl::err::timeout("operation timed out");
        CHECK(e.code == bl::Error::TIMEOUT);
    }

    TEST_CASE("err::crypto creates crypto error") {
        bl::Error e = bl::err::crypto("decryption failed");
        // crypto uses io_error internally
        CHECK(e.code == bl::Error::IO_ERROR);
    }

    TEST_CASE("err::network creates network error") {
        bl::Error e = bl::err::network("connection refused");
        // network uses io_error internally
        CHECK(e.code == bl::Error::IO_ERROR);
    }

    TEST_CASE("err::trust creates trust error") {
        bl::Error e = bl::err::trust("not a member");
        // trust uses permission_denied internally
        CHECK(e.code == bl::Error::PERMISSION_DENIED);
    }

    TEST_CASE("err::config creates config error") {
        bl::Error e = bl::err::config("invalid config");
        // config uses invalid_argument internally
        CHECK(e.code == bl::Error::INVALID_ARGUMENT);
    }

    TEST_CASE("Error message is preserved") {
        bl::Error e = bl::err::io("test message");
        CHECK(e.message == "test message");
    }

}

TEST_SUITE("Result - Error Queries") {

    TEST_CASE("Error is_ok for OK code") {
        bl::Error e = bl::Error::ok();
        CHECK(e.is_ok());
        CHECK_FALSE(e.is_err());
    }

    TEST_CASE("Error is_err for non-OK code") {
        bl::Error e = bl::err::invalid("bad");
        CHECK(e.is_err());
        CHECK_FALSE(e.is_ok());
    }

    TEST_CASE("Error bool conversion") {
        bl::Error ok_err = bl::Error::ok();
        bl::Error bad_err = bl::err::invalid("bad");

        // bool() returns true for error
        CHECK_FALSE(static_cast<bool>(ok_err));
        CHECK(static_cast<bool>(bad_err));
    }

}

TEST_SUITE("Result - Serialization") {

    TEST_CASE("serialize and deserialize simple struct") {
        struct TestData {
            bl::u32 a = 0;
            bl::u32 b = 0;
            auto members() noexcept { return std::tie(a, b); }
            auto members() const noexcept { return std::tie(a, b); }
        };

        TestData original;
        original.a = 123;
        original.b = 456;

        bl::Vector<bl::u8> bytes = bl::serial::serialize(original);
        CHECK(bytes.size() > 0);

        auto result = bl::serial::deserialize<TestData>(bytes);
        REQUIRE(result.is_ok());
        CHECK(result.value().a == 123);
        CHECK(result.value().b == 456);
    }

    TEST_CASE("deserialize with offset") {
        struct Simple {
            bl::u32 value = 0;
            auto members() noexcept { return std::tie(value); }
            auto members() const noexcept { return std::tie(value); }
        };

        Simple data;
        data.value = 999;

        bl::Vector<bl::u8> bytes = bl::serial::serialize(data);

        // Add prefix bytes
        bl::Vector<bl::u8> prefixed;
        prefixed.push_back(0xAA);
        prefixed.push_back(0xBB);
        for (const auto& b : bytes) {
            prefixed.push_back(b);
        }

        auto result = bl::serial::deserialize<Simple>(prefixed, 2);
        REQUIRE(result.is_ok());
        CHECK(result.value().value == 999);
    }

    TEST_CASE("deserialize with invalid offset fails") {
        bl::Vector<bl::u8> small;
        small.push_back(0x01);

        auto result = bl::serial::deserialize<bl::u32>(small, 100);
        CHECK(result.is_err());
    }

    TEST_CASE("deserialize invalid data fails") {
        bl::Vector<bl::u8> garbage;
        garbage.push_back(0xFF);
        garbage.push_back(0xFF);

        auto result = bl::serial::deserialize<bl::String>(garbage);
        CHECK(result.is_err());
    }

}

TEST_SUITE("Result - Result Chaining") {

    TEST_CASE("Chain ok results") {
        auto step1 = []() -> bl::Res<bl::i32> {
            return bl::result::ok(10);
        };

        auto step2 = [](bl::i32 x) -> bl::Res<bl::i32> {
            return bl::result::ok(x * 2);
        };

        auto r1 = step1();
        REQUIRE(r1.is_ok());
        auto r2 = step2(r1.value());
        REQUIRE(r2.is_ok());
        CHECK(r2.value() == 20);
    }

    TEST_CASE("Chain with error propagation") {
        auto step1 = []() -> bl::Res<bl::i32> {
            return bl::result::err(bl::err::invalid("failed"));
        };

        auto step2 = [](bl::i32 x) -> bl::Res<bl::i32> {
            return bl::result::ok(x * 2);
        };

        auto r1 = step1();
        REQUIRE(r1.is_err());
        // Don't call step2 if r1 failed
        (void)step2;  // Suppress unused warning
    }

}

TEST_SUITE("Result - Move Semantics") {

    TEST_CASE("Res with moveable type") {
        bl::Res<bl::Vector<bl::u8>> res = bl::result::ok(bl::Vector<bl::u8>());
        REQUIRE(res.is_ok());

        bl::Vector<bl::u8>& vec = res.value();
        vec.push_back(1);
        vec.push_back(2);

        CHECK(res.value().size() == 2);
    }

    TEST_CASE("String result") {
        bl::Res<bl::String> res = bl::result::ok(bl::String("hello"));
        REQUIRE(res.is_ok());
        CHECK(res.value() == "hello");
    }

}
