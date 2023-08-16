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

class CKeyProvParamRef
{
protected:
	CRYPT_KEY_PROV_PARAM& mstParam;
public:
	CKeyProvParamRef( CRYPT_KEY_PROV_PARAM& stParam ) : mstParam( stParam ) {}
	CKeyProvParamRef( const CKeyProvParamRef& Src ) : mstParam( Src.mstParam ) {}
	~CKeyProvParamRef() {}
	CKeyProvParamRef& operator=( CKeyProvParamRef& Src )
		{
			mstParam.dwParam = Src.mstParam.dwParam;
			mstParam.pbData = Src.mstParam.pbData;
			Src.mstParam.pbData = NULL;
			mstParam.cbData = Src.mstParam.cbData;
			mstParam.dwFlags = Src.mstParam.dwFlags;
		}
	operator CRYPT_KEY_PROV_PARAM&() { return mstParam; }
	operator const CRYPT_KEY_PROV_PARAM&() const { return mstParam; }
	const DWORD param() const { return mstParam.dwParam; }
	const BYTE* data() const { return mstParam.pbData; }
	const DWORD dataSize() const { return mstParam.cbData; }
	const DWORD flags() const { return mstParam.dwFlags; }
};

class CKeyProvInfoPtr
{
protected:
	const CRYPT_KEY_PROV_INFO* mpProvInfo;
	bool mbDelete;
public:
	CKeyProvInfoPtr( const CRYPT_KEY_PROV_INFO& stProvInfo )
		: mpProvInfo( &stProvInfo ), mbDelete( false ) {}
	CKeyProvInfoPtr( BYTE* pProvInfo )
		: mpProvInfo( (CRYPT_KEY_PROV_INFO*)pProvInfo ), mbDelete( true ) {}
	CKeyProvInfoPtr( CKeyProvInfoPtr& Src )
		: mpProvInfo( Src.mpProvInfo ), mbDelete( Src.mbDelete )
		{
			Src.mpProvInfo = NULL;
			Src.mbDelete = false;
		}
	CKeyProvInfoPtr( const CKeyProvInfoPtr& Src )
		: mpProvInfo( Src.mpProvInfo ), mbDelete( false ) {}
	~CKeyProvInfoPtr()
		{
			if( mbDelete )
				delete[] (BYTE*)mpProvInfo;
		}
	CKeyProvInfoPtr& operator=( CKeyProvInfoPtr& Src )
		{
			mpProvInfo = Src.mpProvInfo;
			Src.mpProvInfo = NULL;
			mbDelete = Src.mbDelete;
			Src.mbDelete = false;
		}
	CKeyProvInfoPtr& operator=( const CKeyProvInfoPtr& Src )
		{
			mpProvInfo = Src.mpProvInfo;
			mbDelete = false;
		}
	const CRYPT_KEY_PROV_INFO* operator->() const { return mpProvInfo; }
	operator const CRYPT_KEY_PROV_INFO*() { return mpProvInfo; }
	bool operator!() const { return (mpProvInfo == NULL); }
	const LPWSTR containerName() const { return mpProvInfo? mpProvInfo->pwszContainerName : NULL; }
	const LPWSTR providerName() const { return mpProvInfo? mpProvInfo->pwszProvName : NULL; }
	const DWORD providerType() const { return mpProvInfo? mpProvInfo->dwProvType : 0; }
	const DWORD flags() const { return mpProvInfo? mpProvInfo->dwFlags : 0; }
	const DWORD paramCount() const { return mpProvInfo? mpProvInfo->cProvParam : 0; }
	const CRYPT_KEY_PROV_PARAM* params() const { return mpProvInfo? mpProvInfo->rgProvParam : NULL; }
	const DWORD keySpec() const { return mpProvInfo? mpProvInfo->dwKeySpec : 0; }
	HCRYPTPROV acquireContainer() const
		{
			if( !mpProvInfo )
				return NULL;
			HCRYPTPROV hProv;
			CryptAcquireContextW( &hProv,
														mpProvInfo->pwszContainerName,
														mpProvInfo->pwszProvName,
														mpProvInfo->dwProvType,
														0 );
			return hProv;
		}
	HCRYPTPROV deleteContainer() const
		{
			if( !mpProvInfo )
				return NULL;
			HCRYPTPROV hUnused;
			if( !CryptAcquireContextW( &hUnused,
																 mpProvInfo->pwszContainerName,
																 mpProvInfo->pwszProvName,
																 mpProvInfo->dwProvType,
																 CRYPT_DELETEKEYSET ) )
				return false;
			return true;
		}
};

class CKeyProvInfo : public CRYPT_KEY_PROV_INFO
{
	WCHAR mszContainer[1024];
	WCHAR mszProvName[MAXUIDLEN];
public:
	CKeyProvInfo()
		{
			pwszContainerName = NULL;
			pwszProvName = NULL;
			dwProvType = 0;
			dwFlags = 0;
			cProvParam = 0;
			rgProvParam = NULL;
			dwKeySpec = 0;
		}
	CKeyProvInfo( LPCWSTR pwszContainer,
								LPCWSTR pwszProviderName = MS_DEF_PROV_W,
								DWORD dwProviderType = PROV_RSA_FULL,
								DWORD dwKeySpecIn = AT_KEYEXCHANGE,
								DWORD dwFlagsIn = 0 )
		{
			if( pwszContainer )
			{
				lstrcpynW( mszContainer, pwszContainer, _elements(mszContainer) );
				pwszContainerName = mszContainer;
			}
			else
				pwszContainerName = NULL;
			if( pwszProviderName )
			{
				lstrcpynW( mszProvName, pwszProviderName, _elements(mszProvName) );
				pwszProvName = mszProvName;
			}
			else
				pwszProvName = NULL;
			dwProvType = dwProviderType;
			dwFlags = dwFlagsIn;
			cProvParam = 0;
			rgProvParam = NULL;
			dwKeySpec = dwKeySpecIn;
		}
	CKeyProvInfo( CKeyProvInfo& Src )
		{
			pwszContainerName = Src.pwszContainerName;
			Src.pwszContainerName = NULL;
			pwszProvName = Src.pwszProvName;
			Src.pwszProvName = NULL;
			dwProvType = Src.dwProvType;
			dwFlags = Src.dwFlags;
			cProvParam = Src.cProvParam;
			Src.cProvParam = 0;
			rgProvParam = Src.rgProvParam;
			Src.rgProvParam = NULL;
			dwKeySpec = Src.dwKeySpec;
		}
	~CKeyProvInfo()
		{
		}
	CKeyProvInfo& operator=( CKeyProvInfo& Src )
		{
			pwszContainerName = Src.pwszContainerName;
			Src.pwszContainerName = NULL;
			pwszProvName = Src.pwszProvName;
			Src.pwszProvName = NULL;
			dwProvType = Src.dwProvType;
			dwFlags = Src.dwFlags;
			cProvParam = Src.cProvParam;
			Src.cProvParam = 0;
			rgProvParam = Src.rgProvParam;
			Src.rgProvParam = NULL;
			dwKeySpec = Src.dwKeySpec;
		}
	bool operator!() const { return (pwszProvName != NULL); }
	HCRYPTPROV acquireContainer() const
		{
			HCRYPTPROV hProv;
			CryptAcquireContextW( &hProv,
														pwszContainerName,
														pwszProvName,
														dwProvType,
														0 );
			return hProv;
		}
	bool deleteContainer() const
		{
			HCRYPTPROV hUnused;
			if( !CryptAcquireContextW( &hUnused,
																 pwszContainerName,
																 pwszProvName,
																 dwProvType,
																 CRYPT_DELETEKEYSET ) )
				return false;
			return true;
		}
};

}; //namespace CAPI
