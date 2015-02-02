# (c) 2015, Ian Clegg <ian.clegg@sourcewarp.com>
#
# winrmlib is licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
__author__ = 'ian.clegg@sourcewarp.com'

# The source code in this file was inspired by the work of Matthieu Suiche,
# http://sandman.msuiche.net/, and the information presented released as
# part of the Microsoft Interoperability Initiative:
# http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-DRSR%5D.pdf

from struct import unpack
from struct import error as StructError

def recombine(outbuf):
    return "".join(outbuf[k] for k in sorted(outbuf.keys()))

def xpress_decode(input_buffer):
    output_buffer_ = {}
    output_index = 0
    input_index = 0
    indicator_bit = 0
    nibble_index = 0

    # we are decoding the entire input here, so I have changed
    # the check to see if we're at the end of the output buffer
    # with a check to see if we still have any input left.
    while input_index < len(input_buffer):
        if (indicator_bit == 0):
            # in pseudocode this was indicator_bit = ..., but that makes no
            # sense, so I think this was intended...
            try:
                indicator = unpack("<L", input_buffer[input_index:input_index + 4])[0]
            except StructError:
                return recombine(output_buffer_)

            input_index += 4
            indicator_bit = 32

        indicator_bit = indicator_bit - 1
        # check whether the bit specified by indicator_bit is set or not
        # set in indicator. For example, if indicator_bit has value 4
        # check whether the 4th bit of the value in indicator is set
        if not (indicator & (1 << indicator_bit)):
            try:
                output_buffer_[output_index] = input_buffer[input_index]
            except IndexError:
                return recombine(output_buffer_)

            input_index += 1
            output_index += 1
        else:
            # Get the length. This appears to use a scheme whereby if
            # the value at the current width is all ones, then we assume
            # that it is actually wider. First we try 3 bits, then 3
            # bits plus a nibble, then a byte, and finally two bytes (an
            # unsigned short). Also, if we are using a nibble, then every
            # other time we get the nibble from the high part of the previous
            # byte used as a length nibble.
            # Thus if a nibble byte is F2, we would first use the low part (2),
            # and then at some later point get the nibble from the high part (F).

            try:
                length = unpack("<H", input_buffer[input_index:input_index + 2])[0]
            except StructError:
                return recombine(output_buffer_)

            input_index += 2
            offset = length / 8
            length = length % 8
            if length == 7:
                if nibble_index == 0:
                    nibble_index = input_index
                    length = ord(input_buffer[input_index]) % 16
                    input_index += 1
                else:
                    # get the high nibble of the last place a nibble sized
                    # length was used thus we don't waste that extra half
                    # byte :p
                    length = ord(input_buffer[nibble_index]) / 16
                    nibble_index = 0

                if length == 15:
                    length = ord(input_buffer[input_index])
                    input_index += 1
                    if length == 255:
                        try:
                            length = unpack("<H", input_buffer[input_index:input_index + 2])[0]
                        except StructError:
                            return recombine(output_buffer_)
                        input_index = input_index + 2
                        length = length - (15 + 7)
                    length = length + 15
                length = length + 7
            length = length + 3

            while length != 0:
                try:
                    output_buffer_[output_index] = output_buffer_[output_index - offset - 1]
                except KeyError:
                    return recombine(output_buffer_)
                output_index += 1
                length -= 1

    return recombine(output_buffer_)


class Compressor:

	def __init__(self):
		self.referencePrefix = "`"
		self.referencePrefixCode = ord(self.referencePrefix)
		self.referenceIntBase = 96
		self.referenceIntFloorCode = ord(" ")
		self.referenceIntCeilCode = self.referenceIntFloorCode + self.referenceIntBase - 1
		self.maxStringDistance = self.referenceIntBase ** 2 - 1
		self.minStringLength = 5
		self.maxStringLength = self.referenceIntBase ** 1 - 1 + self.minStringLength
		self.maxWindowLength = self.maxStringDistance + self.minStringLength;
		self.defaultWindowLength = 144

	def compress(self, data, windowLength = None):
		"""Compresses text data using the LZ77 algorithm."""

		if windowLength == None:
			windowLength = self.defaultWindowLength

		compressed = ""
		pos = 0
		lastPos = len(data) - self.minStringLength

		while pos < lastPos:

			searchStart = max(pos - windowLength, 0);
			matchLength = self.minStringLength
			foundMatch = False
			bestMatchDistance = self.maxStringDistance
			bestMatchLength = 0
			newCompressed = None

			while (searchStart + matchLength) < pos:

				m1 = data[searchStart : searchStart + matchLength]
				m2 = data[pos : pos + matchLength]
				isValidMatch = (m1 == m2 and matchLength < self.maxStringLength)

				if isValidMatch:
					matchLength += 1
					foundMatch = True
				else:
					realMatchLength = matchLength - 1

					if foundMatch and realMatchLength > bestMatchLength:
						bestMatchDistance = pos - searchStart - realMatchLength
						bestMatchLength = realMatchLength

					matchLength = self.minStringLength
					searchStart += 1
					foundMatch = False

			if bestMatchLength:
				newCompressed = (self.referencePrefix + self.__encodeReferenceInt(bestMatchDistance, 2) + self.__encodeReferenceLength(bestMatchLength))
				pos += bestMatchLength
			else:
				if data[pos] != self.referencePrefix:
					newCompressed = data[pos]
				else:
					newCompressed = self.referencePrefix + self.referencePrefix
				pos += 1

			compressed += newCompressed

		return compressed + data[pos:].replace("`", "``")

	def decompress(self, data):
		"""Decompresses LZ77 compressed text data"""

		decompressed = ""
		pos = 0
		while pos < len(data):
			currentChar = data[pos]
			if currentChar != self.referencePrefix:
				decompressed += currentChar
				pos += 1
			else:
				nextChar = data[pos + 1]
				if nextChar != self.referencePrefix:
					distance = self.__decodeReferenceInt(data[pos + 1 : pos + 3], 2)
					length = self.__decodeReferenceLength(data[pos + 3])
					start = len(decompressed) - distance - length
					end = start + length
					decompressed += decompressed[start : end]
					pos += self.minStringLength - 1
				else:
					decompressed += self.referencePrefix
					pos += 2

		return decompressed

	def __encodeReferenceInt(self, value, width):
		if value >= 0 and value < (self.referenceIntBase ** width - 1):
			encoded = ""
			while value > 0:
				encoded = chr((value % self.referenceIntBase) + self.referenceIntFloorCode) + encoded
				value = int(value / self.referenceIntBase)

			missingLength = width - len(encoded)
			for i in range(missingLength):
				encoded = chr(self.referenceIntFloorCode) + encoded

			return encoded
 		else:
			raise Exception("Reference value out of range: %d (width = %d)" % (value, width))

	def __encodeReferenceLength(self, length):
		return self.__encodeReferenceInt(length - self.minStringLength, 1)

	def __decodeReferenceInt(self, data, width):
		value = 0
		for i in range(width):
			value *= self.referenceIntBase
			charCode = ord(data[i])
			if charCode >= self.referenceIntFloorCode and charCode <= self.referenceIntCeilCode:
				value += charCode - self.referenceIntFloorCode
			else:
				raise Exception("Invalid char code: %d" % charCode)

		return value

	def __decodeReferenceLength(self, data):
		return self.__decodeReferenceInt(data, 1) + self.minStringLength