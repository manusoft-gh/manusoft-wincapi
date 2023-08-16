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

#include "Crypto.h"
#include "AlgID.h"
#include "CertExt.h"
#include "NameAttr.h"
#include "KeyProvInfo.h"

namespace CAPI
{

__declspec(selectany) FILETIME __EmptyFiletime = { 0 };

const DWORD CERT_DELETE_PRIVATE_KEY_ON_CLOSE_PROP_ID = CERT_FIRST_USER_PROP_ID + 0x145;


class CCertificatePublicKeyInfoPtr
{
	const CERT_PUBLIC_KEY_INFO* mpPublicKeyInfo;
public:
	CCertificatePublicKeyInfoPtr() : mpPublicKeyInfo( NULL ) {}
	CCertificatePublicKeyInfoPtr( const CERT_PUBLIC_KEY_INFO* pPublicKeyInfo ) : mpPublicKeyInfo( pPublicKeyInfo ) {}
	~CCertificatePublicKeyInfoPtr() {}
	operator const CERT_PUBLIC_KEY_INFO*() const { return mpPublicKeyInfo; }
	operator const CERT_PUBLIC_KEY_INFO*&() { return mpPublicKeyInfo; }
	bool operator !() { return (!mpPublicKeyInfo); }
	const CERT_PUBLIC_KEY_INFO*& operator ->() { return mpPublicKeyInfo; }
	const CERT_PUBLIC_KEY_INFO** operator &() { return &mpPublicKeyInfo; }
};

class CCertificatePublicKeyInfoRef : public CERT_PUBLIC_KEY_INFO
{
protected:
	CERT_PUBLIC_KEY_INFO& mstPublicKeyInfo;
public:
	CCertificatePublicKeyInfoRef( CERT_PUBLIC_KEY_INFO& stPublicKeyInfo ) : mstPublicKeyInfo( stPublicKeyInfo ) {}
	CCertificatePublicKeyInfoRef( const CCertificatePublicKeyInfoRef& Src ) : mstPublicKeyInfo( Src.mstPublicKeyInfo ) {}
	~CCertificatePublicKeyInfoRef() {}
	operator const CERT_PUBLIC_KEY_INFO&() const { return mstPublicKeyInfo; }
	operator CERT_PUBLIC_KEY_INFO*() { return &mstPublicKeyInfo; }
};

class CCertificatePublicKeyInfo : public CERT_PUBLIC_KEY_INFO
{
	bool mbDelete;
public:
	CCertificatePublicKeyInfo() : mbDelete( false )
		{
			Algorithm.pszObjId = NULL;
			ObjIdBlobRef( Algorithm.Parameters ) = ObjIdBlob();
			CBitBlobRef( PublicKey ) = CBitBlob();
		}
	CCertificatePublicKeyInfo( CCertificatePublicKeyInfo& Src ) : mbDelete( Src.mbDelete )
		{
			Algorithm.pszObjId = Src.Algorithm.pszObjId;
			Src.Algorithm.pszObjId = NULL;
			ObjIdBlobRef( Algorithm.Parameters ) = ObjIdBlobRef( Src.Algorithm.Parameters );
			CBitBlobRef( PublicKey ) = CBitBlobRef( Src.PublicKey );
		}
	CCertificatePublicKeyInfo( LPSTR pszObjId, ObjIdBlobRef Param, CBitBlobRef Val ) : mbDelete( false )
		{
			Algorithm.pszObjId = pszObjId;
			ObjIdBlobRef( Algorithm.Parameters ) = Param;
			CBitBlobRef( PublicKey ) = Val;
		}
	CCertificatePublicKeyInfo( HCRYPTPROV hProv, DWORD dwKeySpec ) : mbDelete( true )
		{
			Algorithm.pszObjId = NULL;
			ObjIdBlobRef( Algorithm.Parameters ) = ObjIdBlob();
			PublicKey.cbData = 0;
			PublicKey.pbData = NULL;
			DWORD cbPublicKeyInfo = 0;
			if( !CryptExportPublicKeyInfo( hProv,
																		 dwKeySpec,
																		 X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
																		 NULL,
																		 &cbPublicKeyInfo ) )
				return;
			CERT_PUBLIC_KEY_INFO* pPublicKeyInfo = (CERT_PUBLIC_KEY_INFO*)new BYTE[cbPublicKeyInfo];
			if( !CryptExportPublicKeyInfo( hProv,
																		 dwKeySpec,
																		 X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
																		 pPublicKeyInfo,
																		 &cbPublicKeyInfo ) )
			{
				delete[] pPublicKeyInfo;
				return;
			}
			Algorithm.pszObjId = new char[lstrlenA( pPublicKeyInfo->Algorithm.pszObjId ) + 1];
			lstrcpyA( Algorithm.pszObjId, pPublicKeyInfo->Algorithm.pszObjId );
			Algorithm.Parameters.cbData = pPublicKeyInfo->Algorithm.Parameters.cbData;
			Algorithm.Parameters.pbData = new BYTE[Algorithm.Parameters.cbData];
			CopyMemory( Algorithm.Parameters.pbData, pPublicKeyInfo->Algorithm.Parameters.pbData, Algorithm.Parameters.cbData );
			PublicKey.cbData = pPublicKeyInfo->PublicKey.cbData;
			PublicKey.pbData = new BYTE[PublicKey.cbData];
			CopyMemory( PublicKey.pbData, pPublicKeyInfo->PublicKey.pbData, PublicKey.cbData );
			PublicKey.cUnusedBits = pPublicKeyInfo->PublicKey.cUnusedBits;
			delete[] pPublicKeyInfo;
		}
	~CCertificatePublicKeyInfo()
		{
			if( mbDelete )
			{
				delete[] Algorithm.pszObjId;
				delete[] Algorithm.Parameters.pbData;
				delete[] PublicKey.pbData;
			}
		}
	operator CCertificatePublicKeyInfoRef() { return CCertificatePublicKeyInfoRef( *this ); }
};

class CCertificateInfoPtr
{
protected:
	PCERT_INFO mpCertInfo;
public:
	CCertificateInfoPtr() : mpCertInfo( NULL ) {}
	CCertificateInfoPtr( PCERT_INFO pCertInfo ) : mpCertInfo( pCertInfo ) {}
	~CCertificateInfoPtr() {}
	operator const PCERT_INFO&() const { return mpCertInfo; }
	operator PCERT_INFO&() { return mpCertInfo; }
	bool operator !() { return (!mpCertInfo); }
	PCERT_INFO* operator &() { return &mpCertInfo; }
	PCERT_INFO& operator ->() { return mpCertInfo; }
	DWORD version() const { return mpCertInfo? mpCertInfo->dwVersion : 0; }
	IntegerBlobRef serialNumber() const
		{ if( mpCertInfo ) return mpCertInfo->SerialNumber; else return IntegerBlob(); }
	AlgorithmIDRef algorithm() const
		{ if( mpCertInfo ) return mpCertInfo->SignatureAlgorithm; else return AlgorithmID(); }
	CertNameBlobRef issuer() const
		{ if( mpCertInfo ) return mpCertInfo->Issuer; else return CertNameBlob(); }
	const FILETIME& validFrom() const
		{ if( mpCertInfo ) return mpCertInfo->NotBefore; else return __EmptyFiletime; }
	const FILETIME& validUntil() const
		{ if( mpCertInfo ) return mpCertInfo->NotAfter; else return __EmptyFiletime; }
	CertNameBlobRef subject() const
		{ if( mpCertInfo ) return mpCertInfo->Subject; else return CertNameBlob(); }
	CCertificatePublicKeyInfoRef publicKeyInfo() const
		{ if( mpCertInfo ) return mpCertInfo->SubjectPublicKeyInfo; else return CCertificatePublicKeyInfo(); }
	CBitBlobRef issuerId() const
		{ if( mpCertInfo ) return mpCertInfo->IssuerUniqueId; else return CBitBlob(); }
	CBitBlobRef subjectId() const
		{ if( mpCertInfo ) return mpCertInfo->SubjectUniqueId; else return CBitBlob(); }
	DWORD extensionsSize() const { return mpCertInfo->cExtension; }
	CCertExtensionsRef extensions() const
		{
			if( mpCertInfo )
				return CCertExtensionsRef( *(CERT_EXTENSIONS*)&mpCertInfo->cExtension );
			else
				return CCertExtensions();
		}
};

class CCertificateStore
{
protected:
	HCERTSTORE mhCertStore;
public:
	CCertificateStore( HCERTSTORE hCertStore = NULL ) : mhCertStore( hCertStore ) {}
	CCertificateStore( LPCWSTR pszStore )
		: mhCertStore( CertOpenSystemStoreW( NULL, pszStore ) )
		{
		}
	CCertificateStore( LPCSTR pszStore )
		: mhCertStore( CertOpenSystemStoreA( NULL, pszStore ) )
		{
		}
	CCertificateStore( DWORD dwFlags, LPCWSTR pszStore )
		: mhCertStore( CertOpenStore( CERT_STORE_PROV_SYSTEM, 0, NULL, dwFlags, pszStore? pszStore : L"My" ) )
		{
		}
	CCertificateStore( bool bLocalMachine, LPCWSTR pszStore )
		: mhCertStore( CertOpenStore( CERT_STORE_PROV_SYSTEM,
																	0,
																	NULL,
																	bLocalMachine?
																		CERT_SYSTEM_STORE_LOCAL_MACHINE :
																		CERT_SYSTEM_STORE_CURRENT_USER,
																	pszStore ) )
		{
		}
	CCertificateStore( LPCSTR pszStoreProvider,
										 DWORD dwFlags,
										 const void* pvPara,
										 HCRYPTPROV hCryptProv = NULL )
		: mhCertStore( CertOpenStore( pszStoreProvider,
																	X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
																	hCryptProv,
																	dwFlags,
																	pvPara ) )
		{
		}
	CCertificateStore( CCertificateStore& Src ) : mhCertStore( Src.mhCertStore )
		{
			Src.mhCertStore = NULL;
		}
	~CCertificateStore() {}
	operator HCERTSTORE() const { return mhCertStore; }
	operator HCERTSTORE&() { return mhCertStore; }
	bool operator!() { return !mhCertStore; }
	HCERTSTORE* operator&() { return &mhCertStore; }
#if (WINVER > 0x400) //not available in Windows 95 with IE 4.x
	Blob getStoreProperty( DWORD dwPropId )
		{
			if( !mhCertStore )
				return NULL;
			DWORD cbData = 0;
			if( !CertGetStoreProperty( mhCertStore, dwPropId, NULL, &cbData ) )
				return NULL;
			Blob Data( cbData );
			if( !CertGetStoreProperty( mhCertStore, dwPropId, Data, &cbData ) )
				return NULL;
			Data.cbData = cbData;
			return Data;
		}
	bool setStoreProperty( DWORD dwPropId, const BYTE* pbData, DWORD cbData )
		{
			if( !mhCertStore )
				return false;
			BYTE* pBlob = new BYTE[sizeof(CRYPT_DATA_BLOB) + cbData];
			CRYPT_DATA_BLOB& Blob = *(CRYPT_DATA_BLOB*)pBlob;
			Blob.cbData = cbData;
			Blob.pbData = pBlob + sizeof(CRYPT_DATA_BLOB);
			CopyMemory( Blob.pbData, pbData, cbData );
			BOOL bSuccess = CertSetStoreProperty( mhCertStore, dwPropId, 0, &Blob );
			delete[] pBlob;
			return (bSuccess != FALSE);
		}
	template< typename TProp >
	bool setStoreProperty( DWORD dwPropId, const TProp& Prop )
		{
			return setStoreProperty( dwPropId, reinterpret_cast< const BYTE* >(&Prop), sizeof(TProp) );
		}
#endif //(WINVER > 0x400)
};

class CCertificateStoreAuto : public CCertificateStore
{
public:
	CCertificateStoreAuto( HCERTSTORE hCertStore = NULL ) : CCertificateStore( hCertStore ) {}
	CCertificateStoreAuto( LPCWSTR pszStore ) : CCertificateStore( pszStore ) {}
	CCertificateStoreAuto( LPCSTR pszStore ) : CCertificateStore( pszStore ) {}
	CCertificateStoreAuto( DWORD dwFlags, LPCWSTR pszStore ) : CCertificateStore( dwFlags, pszStore ) {}
	CCertificateStoreAuto( bool bLocalMachine, LPCWSTR pszStore ) : CCertificateStore( bLocalMachine, pszStore ) {}
	CCertificateStoreAuto( LPCSTR pszStoreProvider,
												 DWORD dwFlags,
												 const void* pvPara,
												 HCRYPTPROV hCryptProv = NULL )
		: CCertificateStore( pszStoreProvider, dwFlags, pvPara, hCryptProv ) {}
	CCertificateStoreAuto( CCertificateStoreAuto& Src ) : CCertificateStore( Src ) {}
	~CCertificateStoreAuto()
		{
			if( mhCertStore )
				CertCloseStore( mhCertStore,
										#ifdef _DEBUG
												CERT_CLOSE_STORE_CHECK_FLAG
										#else
												0
										#endif
													);
		}
	CCertificateStoreAuto& operator=( const CCertificateStore& Src ) { mhCertStore = (HCERTSTORE)Src; return *this; }
	CCertificateStore detach()
		{
			HCERTSTORE hCertStore = mhCertStore;
			mhCertStore = NULL;
			return hCertStore;
		}
};

class CCertificateContextPtr
{
protected:
	const CERT_CONTEXT* mpCertContext;
public:
	CCertificateContextPtr() : mpCertContext( NULL ) {}
	CCertificateContextPtr( const CERT_CONTEXT* pCertContext ) : mpCertContext( pCertContext ) {}
	~CCertificateContextPtr() {}
	CCertificateContextPtr& operator=( const CERT_CONTEXT* pCertContext ) { mpCertContext = pCertContext; return *this; }
	operator const CERT_CONTEXT*() const { return mpCertContext; }
	bool operator !() const { return (!mpCertContext); }
	const CERT_CONTEXT*& operator ->() { return mpCertContext; }
	const CERT_CONTEXT** operator &() { return &mpCertContext; }
	const CERT_CONTEXT* duplicate() const { return CertDuplicateCertificateContext( mpCertContext ); }
	const CERT_CONTEXT* detach()
		{
			const CERT_CONTEXT* pCertContext = mpCertContext;
			mpCertContext = NULL;
			return pCertContext;
		}
	DWORD encodingType() const { return mpCertContext? mpCertContext->dwCertEncodingType : 0; }
	const BYTE* encodedCert() const { return mpCertContext? mpCertContext->pbCertEncoded : NULL; }
	DWORD encodedCertSize() const { return mpCertContext? mpCertContext->cbCertEncoded : 0; }
	CCertificateInfoPtr certInfo() const { return mpCertContext? mpCertContext->pCertInfo : NULL; }
	CCertificateStore store() const { return mpCertContext? mpCertContext->hCertStore : NULL; }
	Blob getProperty( DWORD dwPropId ) const
		{
			if( !mpCertContext )
				return NULL;
			DWORD cbData = 0;
			if( !CertGetCertificateContextProperty( mpCertContext, dwPropId, NULL, &cbData ) )
				return NULL;
			Blob Prop( cbData );
			if( !Prop )
				return NULL;
			if( !CertGetCertificateContextProperty( mpCertContext, dwPropId, Prop, &cbData ) )
				return NULL;
			Prop.cbData = cbData;
			return Prop;
		}
	bool setProperty( DWORD dwPropId, const BYTE* pbData, DWORD cbData )
		{
			if( !mpCertContext )
				return false;
			BYTE* pBlob = new BYTE[sizeof(CRYPT_DATA_BLOB) + cbData];
			CRYPT_DATA_BLOB& Blob = *(CRYPT_DATA_BLOB*)pBlob;
			Blob.cbData = cbData;
			Blob.pbData = pBlob + sizeof(CRYPT_DATA_BLOB);
			CopyMemory( Blob.pbData, pbData, cbData );
			BOOL bSuccess = CertSetCertificateContextProperty( mpCertContext, dwPropId, 0, &Blob );
			delete[] pBlob;
			return (bSuccess != FALSE);
		}
	template< typename TProp >
	bool setProperty( DWORD dwPropId, const TProp& Prop )
		{
			return setProperty( dwPropId, reinterpret_cast< const BYTE* >(&Prop), sizeof(TProp) );
		}
	CKeyProvInfoPtr provInfo() const
		{
			if( !mpCertContext )
				return NULL;
			DWORD cbProvExt = 0;
			if( !CertGetCertificateContextProperty( mpCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cbProvExt ) )
				return NULL;
			CAPI::BytePtrAuto pProvInfo( cbProvExt );
			if( !CertGetCertificateContextProperty( mpCertContext, CERT_KEY_PROV_INFO_PROP_ID, pProvInfo, &cbProvExt ) )
				return NULL;
			return pProvInfo.detach();
		}
	const FILETIME& validFrom() const
		{
			if( !mpCertContext )
			{
				static FILETIME ftNone = { 0, 0 };
				return ftNone;
			}
			return mpCertContext->pCertInfo->NotBefore;
		}
	const FILETIME& validUntil() const
		{
			if( !mpCertContext )
			{
				static FILETIME ftNone = { 0, 0 };
				return ftNone;
			}
			return mpCertContext->pCertInfo->NotAfter;
		}
};

class CCertificateContextPtrAuto : public CCertificateContextPtr
{
public:
	CCertificateContextPtrAuto() : CCertificateContextPtr() {}
	CCertificateContextPtrAuto( const CERT_CONTEXT* pCertContext )
		: CCertificateContextPtr( pCertContext )
		{}
	CCertificateContextPtrAuto( const CCertificateContextPtrAuto& Src )
		: CCertificateContextPtr( Src.duplicate() )
		{}
	CCertificateContextPtrAuto( CCertificateContextPtr Src, bool bCopy )
		: CCertificateContextPtr( bCopy? Src.duplicate() : Src )
		{}
	CCertificateContextPtrAuto( const CERT_CONTEXT* pCertContext, bool bCopy )
		: CCertificateContextPtr( bCopy? CertDuplicateCertificateContext( pCertContext ) : pCertContext )
		{}
	~CCertificateContextPtrAuto()
		{
			if( mpCertContext )
			{ //delete private key if necessary
				Blob Prop = getProperty( CERT_DELETE_PRIVATE_KEY_ON_CLOSE_PROP_ID );
				if( Prop.pbData && *(bool*)Prop.pbData )
				{
					CKeyProvInfoPtr pProvInfo( provInfo() );
					if( pProvInfo )
					{
						HCRYPTPROV hUnused;
						CryptAcquireContextW( &hUnused,
																	pProvInfo->pwszContainerName,
																	pProvInfo->pwszProvName,
																	pProvInfo->dwProvType,
																	CRYPT_DELETEKEYSET );
					}
					setProperty<bool>( CERT_DELETE_PRIVATE_KEY_ON_CLOSE_PROP_ID, false );
				}
				CertFreeCertificateContext( mpCertContext );
			}
		}
	CCertificateContextPtrAuto& operator =( CCertificateContextPtr Src )
		{
			if( mpCertContext )
				CertFreeCertificateContext( mpCertContext );
			mpCertContext = Src;
			return *this;
		}
	CCertificateContextPtrAuto& operator =( const CERT_CONTEXT* const& pCertContext )
		{
			if( mpCertContext )
				CertFreeCertificateContext( mpCertContext );
			mpCertContext = pCertContext;
			return *this;
		}
};

class CCertificateNameInfoPtr
{
	PCERT_NAME_INFO mpCertNameInfo;
public:
	CCertificateNameInfoPtr() : mpCertNameInfo( NULL ) {}
	CCertificateNameInfoPtr( PCERT_NAME_INFO pCertNameInfo ) : mpCertNameInfo( pCertNameInfo ) {}
	CCertificateNameInfoPtr( BytePtr& pBlock ) : mpCertNameInfo( AsStruct<CERT_NAME_INFO>( pBlock ) ) {}
	~CCertificateNameInfoPtr() {}
	operator const PCERT_NAME_INFO() const { return mpCertNameInfo; }
	operator PCERT_NAME_INFO&() { return mpCertNameInfo; }
	bool operator !() { return (!mpCertNameInfo); }
	PCERT_NAME_INFO& operator ->() { return mpCertNameInfo; }
	PCERT_NAME_INFO* operator &() { return &mpCertNameInfo; }
	DWORD size() { return mpCertNameInfo? mpCertNameInfo->cRDN : 0; }
	const CCertificateNameAttribute* findAttribute( LPCSTR pszObjId ) const
		{
			return (const CCertificateNameAttribute*)CertFindRDNAttr( pszObjId, mpCertNameInfo );
		}
};

class CCertificateNameInfo : public CERT_NAME_INFO
{
public:
	CCertificateNameInfo()
		{
			cRDN = 0;
			rgRDN = NULL;
		}
	CCertificateNameInfo( CCertificateNameInfo& Src )
		{
			cRDN = Src.cRDN;
			Src.cRDN = 0;
			rgRDN = Src.rgRDN;
			Src.rgRDN = NULL;
		}
	CCertificateNameInfo( const CCertificateNameInfo& Src )
		{
			cRDN = Src.cRDN;
			rgRDN = Src.rgRDN;
		}
	CCertificateNameInfo( const CERT_NAME_INFO& Src )
		{
			cRDN = Src.cRDN;
			rgRDN = Src.rgRDN;
		}
	~CCertificateNameInfo() {}
	DWORD size() const { return cRDN; }
	CCertificateNameAttributes* rdn() { return (CCertificateNameAttributes*)rgRDN; }
	const CCertificateNameAttribute* findAttribute( LPCSTR pszObjId ) const
		{
			return (const CCertificateNameAttribute*)CertFindRDNAttr( pszObjId, const_cast<CCertificateNameInfo*>(this) );
		}
};

class CCertificateName : public CertNameBlob
{
public:
	CCertificateName( LPCTSTR pszX500, DWORD dwStrType )
		{
			DWORD cbCertName;
			if( !CertStrToName( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
													pszX500,
													dwStrType,
													NULL,
													NULL,
													&cbCertName,
													NULL ) )

				return;
			if( !setSize( cbCertName ) )
				return;
			CertStrToName( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
										 pszX500,
										 dwStrType,
										 NULL,
										 pbData,
										 &cbCertName,
										 NULL );
		}
		~CCertificateName() {}
	bool isValid() const { return (NULL != data()); }
};

}; //namespace CAPI
