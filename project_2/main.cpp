#include <unittest++/UnitTest++.h>
#include <Cipher.h>
#include <Cipher.cpp>

struct Key4_fixture {
	Cipher * p;
	Key4_fixture() {
		p = new Cipher(4);
	}
	~Key4_fixture() {
		delete p;
	}
};

SUITE(KeyTest)
{
	TEST(ValidKrKey) {
		CHECK_EQUAL("qkuxecoohirftubn", Cipher(4).encrypt("thequickbrounfox"));
		}
	TEST(ValidNotKrKey) {
		CHECK_EQUAL("uro*qbf*ekn*hcu*tiox", Cipher(5).encrypt("thequickbrounfox"));
	}
	TEST(NotIntKey) {
		CHECK_EQUAL("qkuxecoohirftubn", Cipher(4.9).encrypt("thequickbrounfox"));
	}
	TEST(ZeroKey) {
		CHECK_THROW(Cipher cp(0),Error);
	}
	TEST(WeakKey) {
		CHECK_THROW(Cipher cp(1),Error);
	}
	TEST(NegativeKey) {
		CHECK_THROW(Cipher cp(-4),Error);
	}
}
SUITE(EncryptTest)
{
	TEST_FIXTURE(Key4_fixture, UpCaseString) {
		CHECK_EQUAL("QKUXECOOHIRFTUBN", p>encrypt("THEQUICKBROWNFOX"));
	}
	TEST_FIXTURE(Key4_fixture, LowCaseString) {
		CHECK_EQUAL("qkuxecoohirftubn", p- >encrypt("thequickbrownfox"));
	}
	TEST_FIXTURE(Key4_fixture, LowAndUpCaseString) {
		CHECK_EQUAL("QkuxecoohirFTuBn", p - >encrypt("TheQuickBrownFox"));
	}
	TEST_FIXTURE(Key4_fixture, SpaceAndPunctString) {
		CHECK_THROW(p->encrypt("the quick brown fox!!!"),Error);
	}
	TEST_FIXTURE(Key4_fixture, digitString) {
		CHECK_THROW(p- >encrypt("the55quickbrownfox"), Error);
	}
	TEST_FIXTURE(Key4_fixture, EmptyString) {
		CHECK_THROW(p->encrypt(""),Error);
	}
	TEST_FIXTURE(Key4_fixture, noAlphaString) {
		CHECK_THROW(p->encrypt("0123456789"),Error);
	}
	TEST_FIXTURE(Key4_fixture, ShortString) {
		CHECK_THROW(p->encrypt("fox"),Error);
	}
	TEST_FIXTURE(Key4_fixture, EqualKeyString) {
		CHECK_THROW(p->encrypt("true"),Error);
	}
}

SUITE(DecryptTest)
{
	TEST_FIXTURE(Key4_fixture, UpCaseString) {
		CHECK_EQUAL("THEQUICKBROWNFOX", p- >decrypt("QKUXECOOHIRFTUBN"));
	}
	TEST_FIXTURE(Key4_fixture, LowCaseString) {
		CHECK_EQUAL("thequickbrownfox", p- >decrypt("qkuxecoohirftubn"));
	}
	TEST_FIXTURE(Key4_fixture, LowAndUpCaseString) {
		CHECK_EQUAL("TheQuickBrownFox", p- >decrypt("QkuxecoohirFTuBn"));
	}
	TEST_FIXTURE(Key4_fixture, PunctString) {
		CHECK_THROW(p- >decrypt("qkuxe,coohirftubn"), Error);
	}
	TEST_FIXTURE(Key4_fixture, digitString) {
		CHECK_THROW(p- >decrypt("qkuxecoohirftubn55"), Error);
	}
	TEST_FIXTURE(Key4_fixture, EmptyString) {
		CHECK_THROW(p->decrypt(""),Error);
	}
	TEST_FIXTURE(Key4_fixture, SpaceString) {
		CHECK_THROW(p->decrypt("qkuxe coohirftubn"), Error);
	}
	TEST_FIXTURE(Key4_fixture, ShortString) {
		CHECK_THROW(p->decrypt("fox"),Error);
	}
	TEST_FIXTURE(Key4_fixture, EqualKeyString) {
		CHECK_THROW(p->decrypt("true"),Error);
	}
}

int main(int argc, char **argv)
{
	return UnitTest::RunAllTests();
}