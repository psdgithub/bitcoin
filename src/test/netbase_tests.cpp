#include <boost/test/unit_test.hpp>

#include "netbase.h"

using namespace std;

BOOST_AUTO_TEST_SUITE(netbase_tests)

BOOST_AUTO_TEST_CASE(onioncat_test)
{
    // values from http://www.cypherpunk.at/onioncat/wiki/OnionCat
    CNetAddr addr1("5wyqrzbvrdsumnok.onion");
    CNetAddr addr2("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca");
    BOOST_CHECK(addr1 == addr2);
    BOOST_CHECK(addr1.IsTor());
    BOOST_CHECK(addr1.ToStringIP() == "5wyqrzbvrdsumnok.onion");
    BOOST_CHECK(addr1.IsRoutable());
}

BOOST_AUTO_TEST_SUITE_END()
