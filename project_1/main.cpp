#include <unittest++/UnitTest++.h>
#include "modAlphaCipher.h"
#include "modAlphaCipher.cpp"

struct KeyB_fixture {
	modAlphaCipher * p;
	KeyB_fixture() {
		p = new modAlphaCipher("Б");
	}
	~KeyB_fixture() {
		delete p;
	}
};

SUITE(KeyTest)
{
	TEST(ValidKey) {
	CHECK_EQUAL("БВГБВ",modAlphaCipher("БВГ").encrypt("ААААА"));
	}
	TEST(LongKey) {
	CHECK_EQUAL("БВГДЕ",modAlphaCipher("БВГДЕЁЖЗИЙК").encrypt("ААААА"));
	}
	TEST(LowCaseKey) {		CHECK_EQUAL("БВГБВ",modAlphaCipher("бвг").encrypt("ААААА"));
	}
	TEST(DigitsInKey) {
		CHECK_THROW(modAlphaCipher cp("Б1"),cipher_error);
	}
	TEST(PunctuationInKey) {
		CHECK_THROW(modAlphaCipher cp("Б,С"),cipher_error);
	}
	TEST(WhitespaceInKey) {
		CHECK_THROW(modAlphaCipher cp("Б С"), cipher_error);
	}
	TEST(EmptyKey) {
		CHECK_THROW(modAlphaCipher cp(""),cipher_error);
	}
	TEST(WeakKey) {
		CHECK_THROW(modAlphaCipher cp("ААА"),cipher_error);
	}
}

SUITE(EncryptTest)
{
	TEST_FIXTURE(KeyB_fixture, UpCaseString) {
		CHECK_EQUAL("БВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯА",
        p->encrypt("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"));
	}
	TEST_FIXTURE(KeyB_fixture, LowCaseString) {
		CHECK_EQUAL("БВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯА", 
		p->encrypt("абвгдеёжзийклмнопрстуфхцчшщъыьэюя"));
	}
	TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
		CHECK_EQUAL("БВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯА", 
		p->encrypt("АБВГ ДЕЁЖЗИЙ КЛМНОПР СТУФХЦЧ ШЩЪЫЬЭЮ Я!!!"));
	}
	TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
		CHECK_EQUAL("ЙТУЙОБСАЕПН", p->encrypt("Истина Рядом"));
	}
	TEST_FIXTURE(KeyB_fixture, EmptyString) {
		CHECK_THROW(p->encrypt(""),cipher_error);
	}
	TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
		CHECK_THROW(p->encrypt("123423123141"),cipher_error);
	}
	TEST(MaxShiftKey) {
		CHECK_EQUAL("ЯАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮ", 
		modAlphaCipher("Я").encrypt("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"));
	}
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
		CHECK_EQUAL("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ", p->decrypt("БВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯА"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt("бвгДЕЁЖЗИыфвЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯА"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt("БВГД ЕЁЖЗИЙКЛ МНОПРСТУФХ ЦЧШЩЪЫЬЭЮЯА"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt("123БВГДЕЁЖ3131ЩЪЫЬЭЮЯА31"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt("БВГДЕ,Ы,ЬЭЮЯА"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(""),cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ",
	    modAlphaCipher("Я").decrypt("ЯАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮ"));
    }
}

int main(int argc, char **argv)
{
	return UnitTest::RunAllTests();
}