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

typedef CRYPT_DATA_BLOB ANYBLOB;

template< typename TBlobAlias = CRYPT_DATA_BLOB >
class CBlobRef
{
protected:
	TBlobAlias& mstBlob;
public:
	CBlobRef( TBlobAlias& Src )
		: mstBlob( Src )
		{
		}
	CBlobRef( const CBlobRef< TBlobAlias >& Src )
		: mstBlob( Src.mstBlob )
		{
		}
	~CBlobRef() {}
	CBlobRef< TBlobAlias >& operator=( const CBlobRef< TBlobAlias >& Src )
		{
			mstBlob.pbData = Src.mstBlob.pbData;
			mstBlob.cbData = Src.mstBlob.cbData;
			return *this;
		}
	CBlobRef< TBlobAlias >& operator=( TBlobAlias& Src )
		{
			mstBlob.cbData = Src.cbData;
			mstBlob.pbData = Src.pbData;
			Src.cbData = 0;
			Src.pbData = NULL;
			return *this;
		}
	operator TBlobAlias&() { return mstBlob; }
	operator const TBlobAlias&() const { return mstBlob; }
	operator BYTE* const &() const { return mstBlob.pbData; }
	operator BYTE*&() { return mstBlob.pbData; }
	bool operator!() const { return !mstBlob.pbData; }
	BYTE* const & data() const { return mstBlob.pbData; }
	DWORD size() const { return mstBlob.cbData; }
};

typedef CBlobRef< ANYBLOB > BlobRef;
typedef CBlobRef< CRYPT_INTEGER_BLOB > IntegerBlobRef;
typedef CBlobRef< CRYPT_UINT_BLOB > UIntBlobRef;
typedef CBlobRef< CRYPT_OBJID_BLOB > ObjIdBlobRef;
typedef CBlobRef< CERT_NAME_BLOB > CertNameBlobRef;
typedef CBlobRef< CERT_RDN_VALUE_BLOB > CertRDNBlobRef;
typedef CBlobRef< CERT_BLOB > CertBlobRef;
typedef CBlobRef< CRL_BLOB > CRLBlobRef;
typedef CBlobRef< DATA_BLOB > XDataBlobRef;
typedef CBlobRef< CRYPT_DATA_BLOB > DataBlobRef;
typedef CBlobRef< CRYPT_HASH_BLOB > HashBlobRef;
typedef CBlobRef< CRYPT_DIGEST_BLOB > DigestBlobRef;
typedef CBlobRef< CRYPT_DER_BLOB > DERBlobRef;
typedef CBlobRef< CRYPT_ATTR_BLOB > AttrBlobRef;

typedef CBlobRef< const ANYBLOB > BlobConstRef;
typedef CBlobRef< const CRYPT_INTEGER_BLOB > IntegerBlobConstRef;
typedef CBlobRef< const CRYPT_UINT_BLOB > UIntBlobConstRef;
typedef CBlobRef< const CRYPT_OBJID_BLOB > ObjIdBlobConstRef;
typedef CBlobRef< const CERT_NAME_BLOB > CertNameBlobConstRef;
typedef CBlobRef< const CERT_RDN_VALUE_BLOB > CertRDNBlobConstRef;
typedef CBlobRef< const CERT_BLOB > CertBlobConstRef;
typedef CBlobRef< const CRL_BLOB > CRLBlobConstRef;
typedef CBlobRef< const DATA_BLOB > XDataBlobConstRef;
typedef CBlobRef< const CRYPT_DATA_BLOB > DataBlobConstRef;
typedef CBlobRef< const CRYPT_HASH_BLOB > HashBlobConstRef;
typedef CBlobRef< const CRYPT_DIGEST_BLOB > DigestBlobConstRef;
typedef CBlobRef< const CRYPT_DER_BLOB > DERBlobConstRef;
typedef CBlobRef< const CRYPT_ATTR_BLOB > AttrBlobConstRef;


template< typename TBlobAlias = CRYPT_DATA_BLOB >
class CBlob : public TBlobAlias
{
	bool mbDeleteData;
public:
	CBlob() : mbDeleteData( false )
		{
			cbData = 0;
			pbData = NULL;
		}
	CBlob( DWORD cbInit ) : mbDeleteData( true )
		{
			pbData = cbInit > 0? new BYTE[cbInit] : NULL;
			if( pbData )
				cbData = cbInit;
			else
				cbData = 0;
		}
	CBlob( CBlob< TBlobAlias >& Src )
		: mbDeleteData( Src.mbDeleteData )
		{
			cbData = Src.cbData;
			pbData = Src.pbData;
			Src.cbData = 0;
			Src.pbData = NULL;
		}
	CBlob( const CBlob< TBlobAlias >& Src )
		: mbDeleteData( true )
		{
			pbData = new BYTE[Src.cbData];
			if( pbData )
			{
				cbData = Src.cbData;
				CopyMemory( pbData, Src.pbData, cbData );
			}
			else
				cbData = 0;
		}
	CBlob( const TBlobAlias& Src )
		: mbDeleteData( true )
		{
			pbData = new BYTE[Src.cbData];
			if( pbData )
			{
				cbData = Src.cbData;
				CopyMemory( pbData, Src.pbData, cbData );
			}
			else
				cbData = 0;
		}
	CBlob( DWORD cb, BYTE* pb ) : mbDeleteData( false )
		{
			cbData = cb;
			pbData = pb;
		}
	CBlob( DWORD cb, const BYTE* pb ) : mbDeleteData( true )
		{
			pbData = new BYTE[cb];
			if( pbData )
			{
				cbData = cb;
				CopyMemory( pbData, pb, cbData );
			}
			else
				cbData = 0;
		}
	~CBlob()
		{
			if( mbDeleteData )
				delete[] pbData;
		}
	CBlob& operator =( CBlob< TBlobAlias >& Src )
		{
			mbDeleteData = Src.mbDeleteData;
			cbData = Src.cbData;
			pbData = Src.pbData;
			Src.cbData = 0;
			Src.pbData = NULL;
			return *this;
		}
	CBlob& operator =( const CBlob< TBlobAlias >& Src )
		{
			mbDeleteData = true;
			pbData = new BYTE[Src.cbData];
			if( pbData )
			{
				cbData = Src.cbData;
				CopyMemory( pbData, Src.pbData, cbData );
			}
			else
				cbData = 0;
			return *this;
		}
	bool setSize( DWORD cbNew )
		{
			BYTE* pbNew = NULL;
			if( cbNew != 0 )
			{
				pbNew = new BYTE[cbNew];
				if( !pbNew )
					return false;
			}
			if( mbDeleteData )
				delete[] pbData;
			mbDeleteData = true;
			pbData = pbNew;
			cbData = cbNew;
			return true;
		}
	operator BYTE* const &() const { return pbData; }
	operator BYTE*&() { return pbData; }
	bool operator !() const { return !pbData; }
	BYTE* const & data() const { return pbData; }
	DWORD size() const { return cbData; }
};

typedef CBlob< ANYBLOB > Blob;
typedef CBlob< CRYPT_INTEGER_BLOB > IntegerBlob;
typedef CBlob< CRYPT_UINT_BLOB > UIntBlob;
typedef CBlob< CRYPT_OBJID_BLOB > ObjIdBlob;
typedef CBlob< CERT_NAME_BLOB > CertNameBlob;
typedef CBlob< CERT_RDN_VALUE_BLOB > CertRDNBlob;
typedef CBlob< CERT_BLOB > CertBlob;
typedef CBlob< CRL_BLOB > CRLBlob;
typedef CBlob< DATA_BLOB > XDataBlob;
typedef CBlob< CRYPT_DATA_BLOB > DataBlob;
typedef CBlob< CRYPT_HASH_BLOB > HashBlob;
typedef CBlob< CRYPT_DIGEST_BLOB > DigestBlob;
typedef CBlob< CRYPT_DER_BLOB > DERBlob;
typedef CBlob< CRYPT_ATTR_BLOB > AttrBlob;

typedef CBlob< const ANYBLOB > ConstBlob;
typedef CBlob< const CRYPT_INTEGER_BLOB > IntegerConstBlob;
typedef CBlob< const CRYPT_UINT_BLOB > UIntConstBlob;
typedef CBlob< const CRYPT_OBJID_BLOB > ObjIdConstBlob;
typedef CBlob< const CERT_NAME_BLOB > CertNameConstBlob;
typedef CBlob< const CERT_RDN_VALUE_BLOB > CertRDNConstBlob;
typedef CBlob< const CERT_BLOB > CertConstBlob;
typedef CBlob< const CRL_BLOB > CRLConstBlob;
typedef CBlob< const DATA_BLOB > XDataConstBlob;
typedef CBlob< const CRYPT_DATA_BLOB > DataConstBlob;
typedef CBlob< const CRYPT_HASH_BLOB > HashConstBlob;
typedef CBlob< const CRYPT_DIGEST_BLOB > DigestConstBlob;
typedef CBlob< const CRYPT_DER_BLOB > DERConstBlob;
typedef CBlob< const CRYPT_ATTR_BLOB > AttrConstBlob;


class CBitBlobRef
{
protected:
	CRYPT_BIT_BLOB& mstBlob;
public:
	CBitBlobRef( CRYPT_BIT_BLOB& Src ) : mstBlob( Src ) {}
	CBitBlobRef( const CBitBlobRef& Src ) : mstBlob( Src.mstBlob ){}
	~CBitBlobRef() {}
	CBitBlobRef& operator=( const CBitBlobRef& Src )
		{
			mstBlob.pbData = Src.mstBlob.pbData;
			mstBlob.cbData = Src.mstBlob.cbData;
			mstBlob.cUnusedBits = Src.mstBlob.cUnusedBits;
		}
	CBitBlobRef& operator=( CBitBlobRef& Src )
		{
			mstBlob.cbData = Src.mstBlob.cbData;
			mstBlob.pbData = Src.mstBlob.pbData;
			mstBlob.cUnusedBits = Src.mstBlob.cUnusedBits;
			Src.mstBlob.cbData = 0;
			Src.mstBlob.pbData = NULL;
			Src.mstBlob.cUnusedBits = 0;
		}
	operator CRYPT_BIT_BLOB&() { return mstBlob; }
	operator const CRYPT_BIT_BLOB&() const { return mstBlob; }
};

class CBitBlob : public CRYPT_BIT_BLOB
{
	bool mbDeleteData;
public:
	CBitBlob() : mbDeleteData( false )
		{
			cbData = 0;
			pbData = NULL;
			cUnusedBits = 0;
		}
	~CBitBlob()
		{
			if( mbDeleteData )
				delete[] pbData;
		}
	CBitBlob( const CRYPT_BIT_BLOB& Src )
		: mbDeleteData( true )
		{
			pbData = new BYTE[Src.cbData];
			if( pbData )
			{
				cbData = Src.cbData;
				CopyMemory( pbData, Src.pbData, cbData );
				cUnusedBits = Src.cUnusedBits;
			}
			else
			{
				cbData = 0;
				cUnusedBits = 0;
			}
		}
	bool operator !() const { return (!pbData); }
	bool setSize( DWORD cbNew )
		{
			BYTE* pbNew = NULL;
			if( cbNew != 0 )
			{
				pbNew = new BYTE[cbNew];
				if( !pbNew )
					return false;
			}
			if( mbDeleteData )
				delete[] pbData;
			mbDeleteData = true;
			pbData = pbNew;
			cbData = cbNew;
			return true;
		}
	DWORD size() const { return cbData; }
};

class BytePtr
{
protected:
	BYTE* mpBlock;
public:
	BytePtr() : mpBlock( NULL ) {}
	BytePtr( DWORD cbBlock ) : mpBlock( cbBlock > 0? new BYTE[cbBlock] : NULL  ) {}
	BytePtr( BYTE* pBlock ) : mpBlock( pBlock ) {}
	BytePtr( BytePtr& Src ) : mpBlock( Src.mpBlock ) { Src.mpBlock = NULL; }
	BytePtr( Blob& Src ) : mpBlock( Src.pbData ) { Src.pbData = NULL; Src.cbData = 0; }
	virtual ~BytePtr() {}
	BytePtr& operator =( BytePtr& Src ) { mpBlock = Src.mpBlock; Src.mpBlock = NULL; return *this; }
	operator BYTE*() const { return mpBlock; }
	operator BYTE*&() { return mpBlock; }
	BYTE** operator &() { return &mpBlock; }
	bool operator !() const { return (!mpBlock); }
	virtual bool allocate( DWORD cbBlock )
	{
		if( cbBlock == 0 )
		{
			mpBlock = NULL;
			return true;
		}
		mpBlock = new BYTE[cbBlock];
		if( !mpBlock )
		{
			SetLastError( ERROR_OUTOFMEMORY );
			return false;
		}
		return true;
	}
	BYTE* detach() { BYTE* pBlock = mpBlock; mpBlock = NULL; return pBlock; }
};

class BytePtrAuto : public BytePtr
{
public:
	BytePtrAuto() : BytePtr() {}
	BytePtrAuto( DWORD cbBlock ) : BytePtr( cbBlock ) {}
	BytePtrAuto( BYTE* pBlock ) : BytePtr( pBlock ) {}
	BytePtrAuto( Blob& Src ) : BytePtr( Src ) {}
	BytePtrAuto( BytePtrAuto& Src ) : BytePtr( Src ) {}
	virtual ~BytePtrAuto() { delete[] mpBlock; }
	BytePtrAuto& operator =( BytePtrAuto& Src ) { BytePtr::operator =( Src ); return *this; }
	virtual bool allocate( DWORD cbBlock )
	{
		delete[] mpBlock;
		return BytePtr::allocate( cbBlock );
	}
};

template< typename TStruct >
Blob AsBlob( TStruct& Struct )
{
	return Blob( sizeof(Struct), (BYTE*)&Struct );
}

template< typename TStruct >
Blob AsBlob( const TStruct& Struct )
{
	return Blob( sizeof(Struct), (BYTE*)&Struct );
}

template< typename TStruct >
const TStruct* AsStruct( const BytePtr& Block )
{
	return (TStruct*)(BYTE*)Block;
}

template< typename TStruct >
TStruct* AsStruct( BytePtr& Block )
{
	return (TStruct*)(BYTE*)Block;
}

template< typename TStruct >
const TStruct* AsStruct( const Blob& Block )
{
	return (TStruct*)(BYTE*)Block;
}

template< typename TStruct >
TStruct* AsStruct( Blob& Block )
{
	return (TStruct*)(BYTE*)Block;
}

}; //namespace CAPI
