// Copyright 2005 ManuSoft
// https://www.manusoft.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

namespace CAPI
{

class CProvider
{
protected:
	HCRYPTPROV mhProv;
public:
	CProvider() : mhProv( NULL ) {}
	CProvider( HCRYPTPROV hProv ) : mhProv( hProv ) {}
	CProvider( CProvider& Src ) : mhProv( Src.mhProv ) { Src.mhProv = NULL; }
	virtual ~CProvider() {}
	operator HCRYPTPROV() const { return mhProv; }
	operator HCRYPTPROV&() { return mhProv; }
	HCRYPTPROV* operator &() { return &mhProv; }
	HCRYPTPROV detach() { HCRYPTPROV hProv = mhProv; mhProv = NULL; return hProv; }
	//void addRef() { if( mhProv ) CryptContextAddRef( mhProv, NULL, 0 ); }
	void release()
	{
		if( mhProv )
		{
			CryptReleaseContext( mhProv, 0 );
			mhProv = 0;
		}
	}
	bool deleteContainer()
	{
		if( !mhProv )
			return false;
		DWORD dwProvType;
		DWORD cbProvType = sizeof(dwProvType);
		if( !CryptGetProvParam( mhProv, PP_PROVTYPE, (BYTE*)&dwProvType, &cbProvType, 0 ) )
			return false;
		DWORD cbContainer;
		if( !CryptGetProvParam( mhProv, PP_CONTAINER, NULL, &cbContainer, 0 ) )
			return false;
		char* pszContainer = new char[cbContainer];
		if( !CryptGetProvParam( mhProv, PP_CONTAINER, (BYTE*)pszContainer, &cbContainer, 0 ) )
		{
			delete[] pszContainer;
			return false;
		}
		DWORD cbProvider;
		if( !CryptGetProvParam( mhProv, PP_NAME, NULL, &cbProvider, 0 ) )
		{
			delete[] pszContainer;
			return false;
		}
		char* pszProvider = new char[cbProvider];
		if( !CryptGetProvParam( mhProv, PP_NAME, (BYTE*)pszProvider, &cbProvider, 0 ) )
		{
			delete[] pszProvider;
			delete[] pszContainer;
			return false;
		}
		HCRYPTKEY hUnused;
		BOOL bDeleted = CryptAcquireContextA( &hUnused,
																					pszContainer,
																					pszProvider,
																					dwProvType,
																					CRYPT_DELETEKEYSET );
		delete[] pszProvider;
		delete[] pszContainer;
		if( !bDeleted )
			return false;
		release();
		return true;
	}
};

class CProviderAuto : public CProvider
{
public:
	CProviderAuto() : CProvider() {}
	CProviderAuto( HCRYPTPROV hProv ) : CProvider( hProv ) {}
	CProviderAuto( CProviderAuto& Src ) : CProvider( Src.detach() )
		{
		}
	virtual ~CProviderAuto()
		{
			release();
		}
	CProviderAuto& operator=( HCRYPTPROV hProv )
		{
			release();
			mhProv = hProv;
			return *this;
		}
};

class CProviderAutoDelete : public CProvider
{
public:
	CProviderAutoDelete() : CProvider() {}
	CProviderAutoDelete( HCRYPTPROV hProv ) : CProvider( hProv ) {}
	CProviderAutoDelete( CProviderAutoDelete& Src ) : CProvider( Src.detach() )
		{
		}
	virtual ~CProviderAutoDelete()
		{
			deleteContainer();
		}
	HCRYPTPROV detach() { HCRYPTPROV hProv = mhProv; mhProv = NULL; return hProv; }
};

class CKey
{
protected:
	HCRYPTKEY mhKey;
public:
	CKey() : mhKey( NULL ) {}
	CKey( CKey& Src ) : mhKey( Src.mhKey ) { Src.mhKey = NULL; }
	CKey( HCRYPTKEY hKey ) : mhKey( hKey ) {}
	virtual ~CKey() {}
	CKey& operator =( CKey& Src ) { mhKey = Src.mhKey; Src.mhKey = NULL; return *this; }
	operator HCRYPTKEY() const { return mhKey; }
	operator HCRYPTKEY&() { return mhKey; }
	HCRYPTKEY* operator &() { return &mhKey; }
	bool operator !() const { return (mhKey == NULL); }
};

class CKeyAuto : public CKey
{
public:
	CKeyAuto() : CKey() {}
	CKeyAuto( HCRYPTKEY hKey ) : CKey( hKey ) {}
	~CKeyAuto()
		{
			if( mhKey )
				CryptDestroyKey( mhKey );
		}
	CKeyAuto& operator =( HCRYPTKEY hKey )
		{
			if( mhKey )
				CryptDestroyKey( mhKey );
			mhKey = hKey;
			return *this;
		}
	CKeyAuto& operator =( CKeyAuto& Src )
		{
			if( mhKey )
				CryptDestroyKey( mhKey );
			mhKey = Src.mhKey;
			Src.mhKey = NULL;
			return *this;
		}
	HCRYPTKEY release() { HCRYPTKEY hKey = mhKey; mhKey = NULL; return hKey; }
};

class CKeyAndProvider : public CProvider, public CKey
{
public:
	CKeyAndProvider() {}
	CKeyAndProvider( CKeyAndProvider& Src ) : CProvider( Src ), CKey( Src ) {}
	CKeyAndProvider( HCRYPTPROV hProv, HCRYPTKEY hKey ) : CProvider( hProv ), CKey( hKey ) {}
	virtual ~CKeyAndProvider() {}
	operator HCRYPTKEY() const { return mhKey; }
	bool operator !() const { return (mhKey == NULL); }
	CKeyAndProvider* operator &() { return this; }
	HCRYPTPROV provider() const { return mhProv; }
	HCRYPTKEY key() const { return mhKey; }
};

class CHash
{
protected:
	HCRYPTHASH mhHash;
public:
	CHash() : mhHash( NULL ) {}
	CHash( CHash& Src ) : mhHash( Src.mhHash ) { Src.mhHash = NULL; }
	CHash( HCRYPTHASH hHash ) : mhHash( hHash ) {}
	virtual ~CHash() {}
	operator HCRYPTHASH() const { return mhHash; }
	operator HCRYPTHASH&() { return mhHash; }
	HCRYPTHASH* operator &() { return &mhHash; }
	bool operator !() const { return (mhHash == NULL); }
};

class CHashAuto : public CHash
{
public:
	CHashAuto() : CHash() {}
	CHashAuto( HCRYPTHASH hHash ) : CHash( hHash ) {}
	~CHashAuto() { if( mhHash ) CryptDestroyHash( mhHash ); }
	CHashAuto& operator =( HCRYPTHASH hHash )
		{
			if( mhHash )
				CryptDestroyHash( mhHash );
			mhHash = hHash;
			return *this;
		}
	CHashAuto& operator =( CHashAuto& Src )
		{
			if( mhHash )
				CryptDestroyHash( mhHash );
			mhHash = Src.mhHash;
			Src.mhHash = NULL;
			return *this;
		}
	HCRYPTHASH release() { HCRYPTHASH hHash = mhHash; mhHash = NULL; return hHash; }
};

}; //namespace CAPI
