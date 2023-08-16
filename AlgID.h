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

#include "Blob.h"

namespace CAPI
{

class AlgorithmID : public CRYPT_ALGORITHM_IDENTIFIER
{
public:
	AlgorithmID()
		{
			pszObjId = NULL;
			Parameters.cbData = 0;
			Parameters.pbData = NULL;
		}
	AlgorithmID( const CRYPT_ALGORITHM_IDENTIFIER& Src )
		{
			pszObjId = Src.pszObjId? new char[lstrlenA( Src.pszObjId )] : NULL;
			ObjIdBlobRef( Parameters ) = ObjIdBlob( Src.Parameters );
		}
	~AlgorithmID()
		{
		}
};

class AlgorithmIDRef
{
	const CRYPT_ALGORITHM_IDENTIFIER& mstAlgID;
public:
	AlgorithmIDRef( const CRYPT_ALGORITHM_IDENTIFIER& stAlgId ) : mstAlgID( stAlgId )
		{
		}
	AlgorithmIDRef( const AlgorithmIDRef& Src ) : mstAlgID( Src.mstAlgID )
		{
		}
	~AlgorithmIDRef() {}
	operator const CRYPT_ALGORITHM_IDENTIFIER&() const { return mstAlgID; }
};

}; //namespace CAPI
