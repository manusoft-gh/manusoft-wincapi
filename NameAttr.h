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

class CCertificateNameAttributeRef
{
protected:
	CERT_RDN_ATTR& mstAttr;
public:
	CCertificateNameAttributeRef( CERT_RDN_ATTR& stAttr ) : mstAttr( stAttr ) {}
	CCertificateNameAttributeRef( const CCertificateNameAttributeRef& Src ) : mstAttr( Src.mstAttr ) {}
	~CCertificateNameAttributeRef() {}
	CCertificateNameAttributeRef& operator=( CCertificateNameAttributeRef& Src )
		{
			mstAttr.pszObjId = Src.mstAttr.pszObjId;
			Src.mstAttr.pszObjId = NULL;
			mstAttr.dwValueType = Src.mstAttr.dwValueType;
			Src.mstAttr.dwValueType = 0;
			CertRDNBlobRef( mstAttr.Value ) = Src.mstAttr.Value;
		}
	operator CERT_RDN_ATTR&() { return mstAttr; }
	operator const CERT_RDN_ATTR&() const { return mstAttr; }
	const LPSTR objectId() const { return mstAttr.pszObjId; }
	DWORD valueType() const { return mstAttr.dwValueType; }
	const CertRDNBlobRef value() const { return CertRDNBlobRef( mstAttr.Value ); }
};

class CCertificateNameAttribute : public CERT_RDN_ATTR
{
public:
	CCertificateNameAttribute()
		{
			pszObjId = NULL;
			dwValueType = 0;
			Value.cbData = 0;
			Value.pbData = NULL;
		}
	CCertificateNameAttribute( const CCertificateNameAttribute& Src )
		{
			int cbOID = Src.pszObjId? lstrlenA( Src.pszObjId ) + 1 : 0;
			if( cbOID > 0 )
			{
				pszObjId = (LPSTR)new BYTE[cbOID];
				lstrcpynA( pszObjId, Src.pszObjId, cbOID );
			}
			else
				pszObjId = NULL;
			dwValueType = Src.dwValueType;
			CertRDNBlobRef( Value ) = CertRDNBlob( Src.Value );
		}
	CCertificateNameAttribute( const CERT_RDN_ATTR& stAttr )
		{
			int cbOID = stAttr.pszObjId? lstrlenA( stAttr.pszObjId ) + 1 : 0;
			if( cbOID > 0 )
			{
				pszObjId = (LPSTR)new BYTE[cbOID];
				lstrcpynA( pszObjId, stAttr.pszObjId, cbOID );
			}
			else
				pszObjId = NULL;
			dwValueType = stAttr.dwValueType;
			CertRDNBlobRef( Value ) = CertRDNBlob( stAttr.Value );
		}
	~CCertificateNameAttribute()
		{
			delete[] pszObjId;
			delete[] Value.pbData;
		}
	CCertificateNameAttribute& operator=( CCertificateNameAttribute& Src )
		{
			pszObjId = Src.pszObjId;
			Src.pszObjId = NULL;
			dwValueType = Src.dwValueType;
			Src.dwValueType = 0;
			CertRDNBlobRef( Value ) = Src.Value;
		}
	CCertificateNameAttribute& operator=( const CCertificateNameAttribute& Src )
		{
			int cbOID = Src.pszObjId? lstrlenA( Src.pszObjId ) + 1 : 0;
			if( cbOID > 0 )
			{
				pszObjId = (LPSTR)new BYTE[cbOID];
				lstrcpynA( pszObjId, Src.pszObjId, cbOID );
			}
			else
				pszObjId = NULL;
			dwValueType = Src.dwValueType;
			CertRDNBlobRef( Value ) = CertRDNBlob( Src.Value );
		}
	operator CertRDNBlobRef() { return Value; }
	DWORD type() const { return dwValueType; }
	CertRDNBlobConstRef value() const { return Value; }
	CString getValueStr() const
		{
			DWORD cbMax = CertRDNValueToStr( type(),
																			 const_cast<PCERT_RDN_VALUE_BLOB>(&Value),
																			 NULL,
																			 0 );
			if( cbMax <= 1 )
				return CString();
			CString sVal;
			CertRDNValueToStr( type(),
												 const_cast<PCERT_RDN_VALUE_BLOB>(&Value),
												 sVal.GetBuffer( cbMax ),
												 cbMax );
			sVal.ReleaseBuffer();
			return sVal;
		}
};

class CCertificateNameAttributes : public CERT_RDN
{
public:
	CCertificateNameAttributes()
		{
			cRDNAttr = 0;
			rgRDNAttr = NULL;
		}
	CCertificateNameAttributes( CCertificateNameAttributes& Src )
		{
			cRDNAttr = Src.cRDNAttr;
			Src.cRDNAttr = 0;
			rgRDNAttr = Src.rgRDNAttr;
			Src.rgRDNAttr = NULL;
		}
	CCertificateNameAttributes( const CCertificateNameAttributes& Src )
		{
			cRDNAttr = Src.cRDNAttr;
			rgRDNAttr = Src.rgRDNAttr;
		}
	CCertificateNameAttributes( const CERT_RDN& Src )
		{
			cRDNAttr = Src.cRDNAttr;
			rgRDNAttr = Src.rgRDNAttr;
		}
	CCertificateNameAttributes( DWORD cbSize, CERT_RDN_ATTR rSrc[] )
		{
			cRDNAttr = cbSize;
			rgRDNAttr = rSrc;
		}
	~CCertificateNameAttributes() {}
	DWORD size() const { return cRDNAttr; }
	CCertificateNameAttribute* attributes() const { return (CCertificateNameAttribute*)rgRDNAttr; }
};

}; //namespace CAPI
