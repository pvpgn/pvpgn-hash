/*
 * Copyright (C) 1999,2001  Ross Combs (rocombs@cs.nmsu.edu)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#include "common/setup_before.h"
#include <cstdio>
#include <cassert>
#include <stdio.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "common/xalloc.h"
#include "common/util.h"
#include "common/bnetsrp3.h"
#include "common/setup_after.h"

using namespace pvpgn;

void string_to_vector(std::string str, std::vector<unsigned char> &array)
{
	int length = str.length();
	// make sure the input string has an even digit numbers
	if(length%2 == 1)
	{
		str = "0" + str;
		length++;
	}

	// allocate memory for the output array
	array.reserve(length/2);

	std::stringstream sstr(str);
	for(int i=0; i < length/2; i++)
	{
		char ch1, ch2;
		sstr >> ch1 >> ch2;
		int dig1, dig2;
		if(isdigit(ch1)) dig1 = ch1 - '0';
		else if(ch1>='A' && ch1<='F') dig1 = ch1 - 'A' + 10;
		else if(ch1>='a' && ch1<='f') dig1 = ch1 - 'a' + 10;
		if(isdigit(ch2)) dig2 = ch2 - '0';
		else if(ch2>='A' && ch2<='F') dig2 = ch2 - 'A' + 10;
		else if(ch2>='a' && ch2<='f') dig2 = ch2 - 'a' + 10;
		array.push_back(dig1*16 + dig2);
	}
}

void string_to_bytearray(std::string str, unsigned char* &array, int& size)
{
	int length = str.length();
	// make sure the input string has an even digit numbers
	if(length%2 == 1)
	{
		str = "0" + str;
		length++;
	}

	// allocate memory for the output array
	array = new unsigned char[length/2];
	size = length/2;

	std::stringstream sstr(str);
	for(int i=0; i < size; i++)
	{
		char ch1, ch2;
		sstr >> ch1 >> ch2;
		int dig1, dig2;
		if(isdigit(ch1)) dig1 = ch1 - '0';
		else if(ch1>='A' && ch1<='F') dig1 = ch1 - 'A' + 10;
		else if(ch1>='a' && ch1<='f') dig1 = ch1 - 'a' + 10;
		if(isdigit(ch2)) dig2 = ch2 - '0';
		else if(ch2>='A' && ch2<='F') dig2 = ch2 - 'A' + 10;
		else if(ch2>='a' && ch2<='f') dig2 = ch2 - 'a' + 10;
		array[i] = dig1*16 + dig2;
	}
}

int main(int argc, char * argv[])
{
	if(argc < 4){
		std::fprintf(stderr,"too few arguments\n");
		return 1;
	}

	std::string username_arg(argv[1]);
	std::string password_arg(argv[2]);
	std::string salt_arg(argv[3]);

	if(username_arg.empty() || password_arg.empty() || salt_arg.empty()){
		std::fprintf(stderr,"some argument is empty\n");
		return 1;
	}

	if(salt_arg.size() != 64){
		std::fprintf(stderr,"salt must be 64len\n");
		return 1;
	}

	if(password_arg.size() % 2 != 0){
		std::cout << "hex password length must be even";
		return 1;
	}

	unsigned char *salt = NULL;
	int salt_size;
	string_to_bytearray(salt_arg, salt, salt_size);
	std::string salt_bytesString((char *)salt, 32);
	delete [] salt;

	unsigned char *password = NULL;
	int password_size;
	string_to_bytearray(password_arg, password, password_size);
	std::string password_bytesString((char *)password, password_size);
	delete [] password;
	

  BnetSRP3 nls1( username_arg, password_bytesString );
  BigInt salt_bigInt((const unsigned char *)salt_bytesString.c_str(), 32, 4, false);
  nls1.setSalt( salt_bigInt );
  

  BigInt v = nls1.getVerifier();
  unsigned char * v_raw = v.getData(32,4,false);
  std::string v_hexBytes((char *)v_raw, 32);
  xfree(v_raw);
  std::string v_hex;
  std::stringstream SS;
  for(int i = 0; i < v_hexBytes.size(); ++i){
	  SS << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)v_hexBytes.at(i);
  }
  std::cout << SS.str();

  return 0;
}

