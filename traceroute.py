# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select
import sys


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live

        __rtt = 0                       # Round trip time
        __packetIsLost = False            # Flag packet loss
        __destinationIsReached = False

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        def getRtt(self):
            return self.__rtt

        def getPacketIsLost(self):
            return self.__packetIsLost

        def getDestinationIpAddress(self):
            return self.__destinationIpAddress

        def getDestinationIsReached(self):
            return self.__destinationIsReached

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        def setRtt(self, rtt):
            self.__rtt = rtt

        def setPacketIsLost(self, booleanValue):
            self.__packetIsLost = booleanValue

        def setDestinationIsReached(self, booleanValue):
            self.__destinationIsReached = booleanValue

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            if self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier():
                icmpReplyPacket.setIcmpIdentifier_isValid(True)
            print("{}{}".format("Identifier sent: ", self.getPacketIdentifier())) if self.__DEBUG_IcmpPacket else 0
            print("{}{}".format("Identifier received: ", icmpReplyPacket.getIcmpIdentifier())) if self.__DEBUG_IcmpPacket else 0

            if self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber():
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)
            print("{}{}".format("Sequence Number sent: ", self.getPacketSequenceNumber())) if self.__DEBUG_IcmpPacket else 0
            print("{}{}".format("Sequence Number received: ", icmpReplyPacket.getIcmpSequenceNumber())) if self.__DEBUG_IcmpPacket else 0

            if self.getDataRaw() == icmpReplyPacket.getIcmpData():
                icmpReplyPacket.setIcmpData_isValid(True)
            print("{}{}".format("Raw Data sent: ", self.getDataRaw())) if self.__DEBUG_IcmpPacket else 0
            print("{}{}".format("Raw Data received: ", icmpReplyPacket.getIcmpData())) if self.__DEBUG_IcmpPacket else 0
           

            if icmpReplyPacket.getIcmpIdentifier_isValid() and icmpReplyPacket.getIcmpSequenceNumber_isValid() and icmpReplyPacket.getIcmpData_isValid():
                icmpReplyPacket.setIsValidResponse(True)
            #pass

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        # code adapted from https://github.com/avaiyang/ICMP-Traceroute/blob/master/ICMP_Traceroute.py
        def sendTraceRouteRequest(self):

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout) #time out is set to 30
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes

            
            mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
            timeLeft = 30
            pingStartTime = time.time()
            startedSelect = time.time()
            whatReady = select.select([mySocket], [], [], timeLeft)
            endSelect = time.time()
            howLongInSelect = (endSelect - startedSelect)
            if whatReady[0] == []:  # Timeout
                timeToLive = self.getTtl()
                rtt = round((time.time() - pingStartTime) * 1000)
            
                print("{} {}ms * * * Time Out".format(timeToLive, rtt))
                return

            # Read the data from the socket
            recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
            # addr  - address of socket sending data
            timeReceived = time.time()
            timeLeft = timeLeft - howLongInSelect
                
            hostname = ''
            try: 
                hostDetails = gethostbyaddr(addr[0])
                if len(hostDetails) > 0:
                    hostname = hostDetails[0]
            except error as excexception:
               hostname = "unknown"

            # print the time taken to get a response, the ip, adn the hostname
            timeToLive = self.getTtl()
            currentAddr = addr[0]
            rtt = round((time.time() - pingStartTime) * 1000)
            
            print("{} {}ms {} {}".format(timeToLive, rtt, currentAddr, hostname))

            if addr[0] == self.getDestinationIpAddress():
                self.setDestinationIsReached(True)

            
            mySocket.close()
            return


        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout) #time out is set to 30
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                

                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")


                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:                          # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )

                        # raise the packetIsLost flag
                        self.setPacketIsLost(True)

                    elif icmpType == 3:                         # Destination Unreachable
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )
                        # raise the packetIsLost flag
                        self.setPacketIsLost(True)


                        # Parse the error codes 0, 3, 11, and 12
                        if icmpCode == 0:
                            print("Destination Unreachable: Net Unreachable")
                        if icmpCode == 3:
                            print("Destination Unreachable: Port Unreachable")
                        if icmpCode == 11:
                            print("Destination Unreachable: Destination Network Unreachable for type of service")
                        if icmpCode == 12:
                            print("Destination Unreachable: Destination Host Unreachable for Type of Service")

                        # method2 to Parse the error codes for Python 3.0
                        # match icmpCode
                        #   case 0:
                        #       print("Destination Unreachable: Net Unreachable")
                        #   case 3:
                        #       print("Destination Unreachable: Port Unreachable")
                        #   case 11:
                        #        print("Destination Unreachable: Destination Nutwork Unreachable for type of service")
                        #   case 12:
                        #       print("Destination Unreachable: Destination Host Unreachable for Type of Service")



                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr, self)
                        return      # Echo reply is the end and therefore should return

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        __icmpIdentifier_isValid = False
        __icmpSequenceNumber_isValid = False
        __icmpData_isValid = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        def getIcmpIdentifier_isValid(self):
            return self.__icmpIdentifier_isValid

        def getIcmpSequenceNumber_isValid(self):
            return self.__icmpSequenceNumber_isValid

        def getIcmpData_isValid(self):
            return self.__icmpData_isValid

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            self.__icmpIdentifier_isValid = booleanValue

        def setIcmpSequenceNumber_isValid(self, booleanValue):
            self.__icmpSequenceNumber_isValid = booleanValue

        def setIcmpData_isValid(self, booleanValue):
            self.__icmpData_isValid = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #

        def printResultToConsole(self, ttl, timeReceived, addr, icmpPacket):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]

            roundTripTime =  round((timeReceived - timeSent) * 1000)
            icmpPacket.setRtt(roundTripTime)

            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )

            if not self.getIcmpIdentifier_isValid():
                print("Error: Icmp Packet has wrong identifier")
                print("{}{}".format("Identifier sent: ", icmpPacket.getPacketIdentifier()))
                print("{}{}".format("Identifier received: ", self.getIcmpIdentifier()))

            if not self.getIcmpSequenceNumber_isValid():
                print("Error: Icmp Packet has wrong sequence number")
                print("{}{}".format("Sequence Number sent: ", icmpPacket.getPacketSequenceNumber()))
                print("{}{}".format("Sequence Number received: ", self.getIcmpSequenceNumber()))

            if not self.getIcmpData_isValid():
                print("Error: Icmp Packet has wrong data")
                print("{}{}".format("Raw Data sent: ", icmpPacket.getDataRaw()))
                print("{}{}".format("Raw Data received: ", self.getIcmpData()))

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        roundTripTimeList = []
        numberOfPackets = 4
        lostPackets = 0

        for i in range(numberOfPackets):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()                                                # Build IP

            # record each of the rtt in an array or a list
            roundTripTimeList.append(icmpPacket.getRtt())

            # increment number of lost packet if packet is lost
            if icmpPacket.getPacketIsLost():
                lostPackets += 1


            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0


            # we should be confirming values are correct, such as identifier and sequence number and data

        # calculate the the Min, Max, and Average rrt
        roundTripTimeList.sort()
        minRtt = round(roundTripTimeList[0])
        maxRtt = round(roundTripTimeList[-1])
        avgRtt = round(sum(roundTripTimeList) / len(roundTripTimeList)) 

        # calculate the packet loss rate  lost/numberOfPackets
        packetLossRate = round (lostPackets/ numberOfPackets, 2)

        # print packet loss rate
        print("Packets: Sent = {}, Received = {}, Lost = {} ({} % loss)".format(numberOfPackets, numberOfPackets-lostPackets, lostPackets, round(packetLossRate * 100)))


        # print out the round trip time
        print("Approximate round trip times in milli-seconds:")
        print("Minimum = {}ms, Maximum = {}ms, Average = {}ms".format(minRtt, maxRtt, avgRtt))

        # print the packet loss rate

    # code adapted from https://dnaeon.github.io/traceroute-in-python/
    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # set the max number hops allowed
        maxHops = 30

        print("Traceroute to {0} over maximum of {1} hops". format(host, maxHops))

        # set the initial ttl and id number
        timeToLive = 1
        id = 1
        
        while True:            # stop the loop when the maxHops number is reached
            # build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()
            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = id

            # set the time-to-live value per each iteration
            icmpPacket.setTtl(timeToLive)

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendTraceRouteRequest()
            

            # if the destination is reached, or the maxHops is reached, break out of the loop
            if icmpPacket.getDestinationIsReached() or timeToLive >= maxHops:
                break


            # if the destination is not reached, increment the ttl
            timeToLive += 1
            id += 1

        #os._exit(0)


    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()


    # Choose one of the following by uncommenting out the line

    #icmpHelperPing.sendPing("www.chinadailyhk.com") #ip in Hong Kong
    #icmpHelperPing.sendPing("www.google.com")
    #icmpHelperPing.sendPing("en.wikipedia.org")
    icmpHelperPing.sendPing("www.louvre.fr")   # ip in France
    

    
    #icmpHelperPing.traceRoute("www.chinadailyhk.com")
    #icmpHelperPing.traceRoute("www.google.com")
    #icmpHelperPing.traceRoute("en.wikipedia.org")
    #icmpHelperPing.traceRoute("www.louvre.fr")   #ip in France



if __name__ == "__main__":
    main()


### Sources:
### Explanation about what Ping and Traceroute do:
### https://www.youtube.com/watch?v=vJV-GBZ6PeM

### How does Traceroute(8) program perform the route tracing:
### https://man7.org/linux/man-pages/man8/traceroute.8.html

### A simple traceroute(8) implementation in Python
### https://dnaeon.github.io/traceroute-in-python/

### Ping results explanied | NETVN
### https://www.youtube.com/watch?v=OwXClvHvuKc
