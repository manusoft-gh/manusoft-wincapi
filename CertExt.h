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

class CCertExtensionRef
{
protected:
	CERT_EXTENSION& mstExt;
public:
	CCertExtensionRef( CERT_EXTENSION& stExt ) : mstExt( stExt ) {}
	CCertExtensionRef( const CCertExtensionRef& Src ) : mstExt( Src.mstExt ) {}
	~CCertExtensionRef() {}
	CCertExtensionRef& operator=( CCertExtensionRef& Src )
		{
			mstExt.pszObjId = Src.mstExt.pszObjId;
			Src.mstExt.pszObjId = NULL;
			mstExt.fCritical = Src.mstExt.fCritical;
			Src.mstExt.fCritical = FALSE;
			ObjIdBlobRef( mstExt.Value ) = Src.mstExt.Value;
		}
	operator CERT_EXTENSION&() { return mstExt; }
	operator const CERT_EXTENSION&() const { return mstExt; }
	const LPSTR objectId() const { return mstExt.pszObjId; }
	BOOL critical() const { return mstExt.fCritical; }
	const ObjIdBlobRef value() const { return mstExt.Value; }
};

class CCertExtension : public CERT_EXTENSION
{
public:
	CCertExtension()
		{
			pszObjId = NULL;
			fCritical = FALSE;
			Value.cbData = 0;
			Value.pbData = NULL;
		}
	CCertExtension( const CCertExtension& Src )
		{
			int cbOID = Src.pszObjId? lstrlenA( Src.pszObjId ) + 1 : 0;
			if( cbOID > 0 )
			{
				pszObjId = (LPSTR)new BYTE[cbOID];
				lstrcpynA( pszObjId, Src.pszObjId, cbOID );
			}
			else
				pszObjId = NULL;
			fCritical = Src.fCritical;
			ObjIdBlobRef( Value ) = ObjIdBlob( Src.Value );
		}
	CCertExtension( CCertExtension& Src )
		{
			pszObjId = Src.pszObjId;
			Src.pszObjId = NULL;
			fCritical = Src.fCritical;
			Src.fCritical = FALSE;
			ObjIdBlobRef( Value ) = Src.Value;
		}
	CCertExtension( const CERT_EXTENSION& stExt )
		{
			int cbOID = stExt.pszObjId? lstrlenA( stExt.pszObjId ) + 1 : 0;
			if( cbOID > 0 )
			{
				pszObjId = (LPSTR)new BYTE[cbOID];
				lstrcpynA( pszObjId, stExt.pszObjId, cbOID );
			}
			else
				pszObjId = NULL;
			fCritical = stExt.fCritical;
			ObjIdBlobRef( Value ) = ObjIdBlob( stExt.Value );
		}
	CCertExtension( LPCSTR pszOID, BOOL bCritical, const ObjIdBlobRef Val )
		{
			int cbOID = pszOID? lstrlenA( pszOID ) + 1 : 0;
			if( cbOID > 0 )
			{
				pszObjId = (LPSTR)new BYTE[cbOID];
				lstrcpynA( pszObjId, pszOID, cbOID );
			}
			else
				pszObjId = NULL;
			fCritical = bCritical;
			ObjIdBlobRef( Value ) = Val;
		}
	~CCertExtension()
		{
			delete[] pszObjId;
			delete[] Value.pbData;
		}
	CCertExtension& operator=( CCertExtension& Src )
		{
			pszObjId = Src.pszObjId;
			Src.pszObjId = NULL;
			fCritical = Src.fCritical;
			Src.fCritical = FALSE;
			ObjIdBlobRef( Value ) = Src.Value;
		}
	CCertExtension& operator=( const CCertExtension& Src )
		{
			int cbOID = Src.pszObjId? lstrlenA( Src.pszObjId ) + 1 : 0;
			if( cbOID > 0 )
			{
				pszObjId = (LPSTR)new BYTE[cbOID];
				lstrcpynA( pszObjId, Src.pszObjId, cbOID );
			}
			else
				pszObjId = NULL;
			fCritical = Src.fCritical;
			ObjIdBlobRef( Value ) = ObjIdBlob( Src.Value );
		}
	ObjIdBlobRef value() { return Value; }
};

class CCertExtensionsRef : public CERT_EXTENSIONS
{
protected:
	const CERT_EXTENSIONS& mstExtensions;
public:
	CCertExtensionsRef( CERT_EXTENSIONS& stExtensions ) : mstExtensions( stExtensions ) {}
	CCertExtensionsRef( const CCertExtensionsRef& Src ) : mstExtensions( Src.mstExtensions ) {}
	~CCertExtensionsRef() {}
	operator const CERT_EXTENSIONS&() const { return mstExtensions; }
	DWORD size() const { return mstExtensions.cExtension; }
	const PCERT_EXTENSION data() const { return mstExtensions.rgExtension; }
};

class CCertExtensions : public CERT_EXTENSIONS
{
	bool mbDelete;
public:
	CCertExtensions() : mbDelete( false )
		{
			cExtension = 0;
			rgExtension = NULL;
		}
	CCertExtensions( CCertExtensions& Src ) : mbDelete( Src.mbDelete )
		{
			cExtension = Src.cExtension;
			rgExtension = Src.rgExtension;
			Src.cExtension = 0;
			Src.rgExtension = NULL;
		}
	CCertExtensions( DWORD cExt, const PCERT_EXTENSION rExt ) : mbDelete( false )
		{
			cExtension = cExt;
			rgExtension = rExt;
		}
	CCertExtensions( const CERT_EXTENSION& stCertExtension ) : mbDelete( true )
		{
			cExtension = 1;
			rgExtension = new CCertExtension[1];
			rgExtension[0] = CCertExtension( stCertExtension );
		}
	CCertExtensions( LPCSTR pszObjId, BOOL bCritical, const ObjIdBlobRef Val ) : mbDelete( true )
		{
			cExtension = 1;
			rgExtension = new CCertExtension[1];
			rgExtension[0] = CCertExtension( pszObjId, bCritical, Val );
		}
	~CCertExtensions()
		{
			if( mbDelete )
				delete[] (CCertExtension*)rgExtension;
		}
	DWORD size() const { return cExtension; }
	const PCERT_EXTENSION data() const { return rgExtension; }
};

}; //namespace CAPI
