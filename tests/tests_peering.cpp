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

        std::this_thread::sleep_for(1000ms); // wait lock is acquired

        std::cout << std::time(nullptr) << ": deleting y\n";
        delete y;
        std::cout << std::time(nullptr) << ": deleted y\n";
    });


    {
        auto[ptr, l_] = x->peering.peer();
        std::cout << std::time(nullptr) << ": having lock\n";
        std::this_thread::sleep_for(5000ms); // wait y is deleted

        if (ptr) {
            std::cout << "Y is valid\n";
            std::cout << "Y.a = " << ptr->a << "\n";
        } else {
            std::cout << "Y is NOT valid\n";
        }
    }
    y_deleter.join();

}