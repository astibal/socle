#include <socle/common/ptr_cache.hpp>
#include <gtest/gtest.h>

struct SomeObject {
    SomeObject() = default;
    SomeObject(int x, int y) : a(x), b(y) {}
    int a;
    int b;

    [[nodiscard]] std::string str() const { return string_format("{ %d, %d }", a, b); }
};


TEST(PtrCacheTest, CanCreate) {

    ptr_cache<std::string, SomeObject> c("mycache", 10, true);
}


TEST(PtrCacheTest, CanAdd) {
    ptr_cache<std::string, SomeObject> c("mycache", 10, true);

    auto one = std::make_shared<SomeObject>();
    c.set("a", one);

    ASSERT_TRUE(one.use_count() == 2);
}

TEST(PtrCacheTest, CanDestroy) {

    constexpr int cache_size = 10;
    ptr_cache<std::string, SomeObject> c("mycache", cache_size, true);

    auto v = std::vector<std::shared_ptr<SomeObject>>();

    constexpr int len = 21;
    for(int i = 0; i < len; i++) {
        auto a = std::make_shared<SomeObject>(i,i);
        v.push_back(a);
        c.set(string_format("%d", i), a);
    }

    ASSERT_TRUE(c.cache().size() == 10);

    std::cerr << "\n\nCanDestroy:" << std::endl;
    for(int i = 0; i < len; i++) {
        if(i < len - cache_size) {
            ASSERT_TRUE(v[i].use_count() == 1);
        }
        else {
            ASSERT_TRUE(v[i].use_count() == 2);
        }

        std::cerr << i << " -> { " << v[i]->a << ", " << v[i]->b << "}, use count: " << v[i].use_count() << std::endl;
    }
}

TEST(PtrCacheTest, CanErase) {

    constexpr int cache_size = 10;
    constexpr int data_len = 21;
    ptr_cache<std::string, SomeObject> c("mycache", cache_size, true);

    auto v = std::vector<std::shared_ptr<SomeObject>>();

    for (int i = 0; i < data_len; i++) {
        auto a = std::make_shared<SomeObject>(i, i);
        v.push_back(a);
        c.set(string_format("%d", i), a);
    }

    c.erase("20");
    ASSERT_TRUE(c.cache().size() == cache_size - 1);
    ASSERT_TRUE(v[20].use_count() == 1);

    std::cerr << "\n\nCanErase:" << std::endl;
    for(int i = 0; i < data_len; i++) {
        std::cerr << i << " -> { " << v[i]->a << ", " << v[i]->b << "}, use count: " << v[i].use_count() << std::endl;
    }

    ASSERT_TRUE(! c.get("20") );
}

TEST(LruPtrCacheTest, CanReorder) {

    constexpr int cache_size = 10;
    constexpr int data_len = 21;
    ptr_cache<std::string, SomeObject> c("mycache", cache_size, true);
    c.mode_lru();

    auto v = std::vector<std::shared_ptr<SomeObject>>();

    for (unsigned int i = 0; i < data_len; i++) {
        auto a = std::make_shared<SomeObject>(i, i);
        v.push_back(a);
        c.set(string_format("%d", i), a);
    }

    c.get("11");

    // verify last element was reordered after get()
    ASSERT_TRUE(c.items().front() == "11");
    c.get("11");
    c.get("11");

    // verify it's still there with correct counter
    ASSERT_TRUE(c.items().front() == "11" and c.cache()["11"]->count() == 3);

    c.set("new", std::make_shared<SomeObject>(99,99));
    ASSERT_TRUE(c.items().front() == "new");
    c.get("13");
    c.get("13");

    c.get("15");
    c.get("15");
    c.get("15");

    c.get("14");
//    // verify '13' is with higher counter still on top
//    ASSERT_TRUE(c.items().front() == "13" and c.cache()["13"].count() == 2);
//
//
    c.set("new1", std::make_shared<SomeObject>(99,1));
    c.set("new2", std::make_shared<SomeObject>(99,2));
//
//    // verify '15' from the end is not dropped
//    auto it_1 = c.items().begin(); it_1++;
//    ASSERT_TRUE(*it_1 == "15" and c.cache()["15"].count() == 3);
//
    c.set("new3", std::make_shared<SomeObject>(99,3));
    c.set("new4", std::make_shared<SomeObject>(99,4));
    c.set("new5", std::make_shared<SomeObject>(99,5));
    c.set("new6", std::make_shared<SomeObject>(99,6));
    c.set("new7", std::make_shared<SomeObject>(99,7));
    c.set("new8", std::make_shared<SomeObject>(99,8));
    c.set("new9", std::make_shared<SomeObject>(99,9));


    std::cerr << "\n\nLru CanReorder:" << std::endl;
    {
        auto it = c.items().begin();
        for (unsigned int i = 0; i < c.items().size(); i++, it++) {
            auto key = *it;
            auto& elem = c.cache()[key];

            std::cerr << i << " -> " << key << "[" << elem->count() << "] -> " << elem->ptr()->str() << std::endl;
        }
    }

    ASSERT_TRUE(c.cache().size() == c.items().size());

    std::cerr << "\n\nLru CanReorder (orig data list):" << std::endl;
    for(int i = 0; i < data_len; i++) {
        std::cerr << i << " -> { " << v[i]->a << ", " << v[i]->b << "}, use count: " << v[i].use_count() << std::endl;
    }
}
