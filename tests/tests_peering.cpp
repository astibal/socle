#include <peering.hpp>

#include <gtest/gtest.h>
#include <thread>


struct A {
    int a{0};
    Peering<A> peering{this};
    PeeringGuard<A> p{peering};

    virtual ~A() { a = -666; }
};

struct B : public A {
    int b{0};
    PeeringGuard<A> p{peering};

    virtual ~B() { b = -665; }
};


TEST(PeeringTest, YNotValid) {

    B x;
    {
        B y;

        x.peering.attach(y.peering);
        y.peering.attach(x.peering);
        // y is gone
    }

    auto [ ptr, l_ ] = x.peering.peer();

    if(ptr) {
        std::cout << "Y is valid\n";
    } else {
        std::cout << "Y is NOT valid\n";
    }

    ASSERT_FALSE(ptr);
}


TEST(PeeringTest, YThread) {

    using namespace std::chrono_literals;
    auto x = new B();
    auto y = new B();
    x->a = 10;
    x->b = 11;

    y->a = 20;
    y->b = 21;


    {

        x->peering.attach(y->peering);
        y->peering.attach(x->peering);
        // y is gone
    }

    std::thread y_deleter([y]() {

        std::this_thread::sleep_for(500ms); // wait lock is acquired

        std::cout << std::time(nullptr) << ": deleting y\n";
        delete y;
        std::cout << std::time(nullptr) << ": deleted y\n";
    });

    {
        auto[ptr, l_] = x->peering.peer();
        std::cout << std::time(nullptr) << ": having lock\n";
        std::this_thread::sleep_for(1600ms); // wait y is deleted

        ASSERT_TRUE(ptr);

        if (ptr) {
            std::cout << std::time(nullptr) << ": Y is valid\n";
            std::cout << std::time(nullptr) << ": Y.a = " << ptr->a << "\n";

            // destructor would rewrite 20 to -66x, anything else than 20 would mean invalid memory access
            ASSERT_TRUE(ptr->a == 20);

            // does peer is peering with us, too?
            ASSERT_TRUE(dynamic_cast<B*>(ptr->peering.peer().first) == x);
        } else {
            std::cout << std::time(nullptr) << ": Y is NOT valid\n";
        }
    }
    y_deleter.join();

    delete x;
}