//�������� ��������, ���� �� ������� �������� ������� ����� � CRYPT_NEWKEYSET
//���������� ���� ������(������������� ����������)
//���������� ���������� ����(������������ ����������)
//����� �������� �����, ������� ��� ���������� ������
//���������� ���� ������� ��������� ������ �� ����
//... �������� ����������� ����� + ����������� ���������� ���� ...
//��������� ���������� ���� ��������� ������ �� ����
//��������� ����� ���������� ������

#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <fstream>

#pragma lib("crypt32.dll")

using namespace std;

void Error(string text)
{
	cout << "[ERROR] " << text << endl;
}

HCRYPTKEY get_session_key_without_pass(HCRYPTPROV provider)
{
	HCRYPTKEY session_key;
	if (auto res = !CryptGenKey(provider, CALG_AES_256, CRYPT_EXPORTABLE, &session_key))
	{
		Error("CryptGenKey Session Key");
		return NULL;
	}
	return session_key;
}
HCRYPTKEY get_session_key_with_pass(HCRYPTPROV provider)
{
	string password;
	cout << "Enter pass: ";
	cin >> password;
	HCRYPTKEY session_key;
	HCRYPTHASH hash;
	if (!CryptCreateHash(provider, CALG_SHA_256, NULL, 0, &hash))
	{
		Error("CreateHash");
		return NULL;
	}
	if (!CryptHashData(hash, (BYTE*)password.c_str(), password.length(), 0))
	{
		Error("HashData");
		return NULL;
	}
	if (!CryptDeriveKey(provider, CALG_AES_256, hash, 0, &session_key))
	{
		Error("DeriveKey");
		return NULL;
	}
	
	CryptDestroyHash(hash);
	return session_key;
}

vector<char> encrypt_text(string t, HCRYPTKEY key)
{
	vector<char> res;
	DWORD pdwLen = strlen(t.c_str());
	if (!CryptEncrypt(key, NULL, true, 0, NULL, &pdwLen, 0))
		Error("CryptEncrypt1");
	res.resize(pdwLen);
	if (!CryptEncrypt(key, NULL, true, 0, (BYTE*)res.data(), &pdwLen, pdwLen))
		Error("CryptEncrypt2");

	return res;
}

vector<char> read_file(string path)
{
	ifstream reader(path, ios::binary);
	if (reader.is_open() == false)
		cout << "Read File Error. File doesn't exist" << endl;
	vector<char> v(istreambuf_iterator<char>{reader}, {});
	reader.close();
	return v;
}
void write_file(string path, vector<char> text)
{
	ofstream writer(path, ios::binary);
	writer.write(text.data(), text.size());
	writer.close();
}

int main()
{
	setlocale(LC_ALL, "Russian");
	HCRYPTPROV provider;
	/// MS_ENH_RSA_AES_PROV - ����� ��������� ��� �������� � RSA & AES ����������� ����������
	/// PROV_RSA_AES - ����� ������� ����� �� ��������� RSA, ������� ����� �����������/������������� �� RSA,
	/// � ���������� ������ ����� ����������� �� AES
	/// ���� ����� ������������ ������ RSA, ��� AES, �� ��������� ��������� �������� PROV_RSA_FULL
	
	if (!CryptAcquireContext(&provider, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			Error("CryptAcquireContext BAD_KEYSET");
			if (!CryptAcquireContext(&provider, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET))
			{
				Error("CryptAcquireContext");
				return 0;
			}
		}
		Error("CryptAcquireContext");
	}

	/// � ����� �����, ��� ��� �������� ����� ������� CRYPT_ENCRYPT ��� ����������� ����������� 
	/// & CRYPT_DECRYPT, ���� ������������ ������. ���� �� �������� CRYPT_ENCRYPT | CRYPT_DECRYPT - ������� ������
	/// ������ CRYPT_EXPORTABLE, �����, ������� ���� �� ���������� � �������� �����.
	/// todo: ���������, ������� �� ���� ����� ��������� �� ����������

	HCRYPTKEY session_key;
	int is_pass;
	cout << "����� ������?(0/1): ";
	cin >> is_pass;
	if (is_pass == 0) session_key = get_session_key_without_pass(provider);
	else session_key = get_session_key_with_pass(provider);

	// �������� ���������� ����
	// ������� �����
	auto text = read_file("base_text.txt");
	string t = "";
	for (auto c : text) t += c;
	auto crypted_text = encrypt_text(t,session_key);
	for (auto c : crypted_text)
		cout << c;
	return 0;
}