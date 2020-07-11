import struct
import os

def from2BLittleEndian(n1,n2):
    return (n2<<8)+n1

def from4BLittleEndian(n1,n2,n3,n4):
    return (n4<<24)+(n3<<16)+(n2<<8)+(n1)

def get4BLittleEndian(data):
    n1 = data&0x000000FF
    n2 = (data&0x0000FF00) >> 8
    n3 = (data&0x00FF0000) >> 16
    n4 = (data&0xFF000000) >> 24 
    return [n1,n2,n3,n4]

def binToInt(dataBin):
    dataTuple = struct.unpack('B',dataBin)
    return dataTuple[0]

def intToBin(dataInt):
     b = struct.pack('B', dataInt)
     return b
 
def getMsgFromBin(fileBin,offset,size):
    if size == 4:
        fileBin.seek(offset)
        b1 = fileBin.read(1)
        b2 = fileBin.read(1)
        b3 = fileBin.read(1)
        b4 = fileBin.read(1)
        n1 = binToInt(b1)
        n2 = binToInt(b2)
        n3 = binToInt(b3)
        n4 = binToInt(b4)
        return from4BLittleEndian(n1,n2,n3,n4)
    elif size == 2:
        fileBin.seek(offset)
        b1 = fileBin.read(1)
        b2 = fileBin.read(1)
        n1 = binToInt(b1)
        n2 = binToInt(b2)
        return from2BLittleEndian(n1,n2)
    elif size == 1:
        fileBin.seek(offset)
        b1 = fileBin.read(1)
        n1 = binToInt(b1)
        return n1
    else:
        return -1
    
def getBinFromData(msg,size):
    if size == 4:
        [n1,n2,n3,n4] = get4BLittleEndian(msg)
        b1 = intToBin(n1)
        b2 = intToBin(n2)
        b3 = intToBin(n3)
        b4 = intToBin(n4)
        return [b1,b2,b3,b4]
    else:
        return -1

def getSectionMsg(fileBin):
    sectionHeaderOffset = getMsgFromBin(fileBin,0x20,4)
    sectionNum = getMsgFromBin(fileBin,0x30,2)
    shStrTabIndex = getMsgFromBin(fileBin,0x32,2)
    return [sectionHeaderOffset,sectionNum,shStrTabIndex]

def getProgramMsg(fileBin):
    programHeaderOffset = getMsgFromBin(fileBin,0x1C,4)
    programNum = getMsgFromBin(fileBin,0x2C,2)
    return [programHeaderOffset,programNum]
    
def getShStrTabMsg(fileBin,sectionHeaderOffset,shStrTabIndex):
    shStrTabSectionHeaderOffset = sectionHeaderOffset + shStrTabIndex * 0x28
    shStrTabSectionOffset = getMsgFromBin(fileBin,shStrTabSectionHeaderOffset + 0x10,4)
    shStrTabSectionSize = getMsgFromBin(fileBin,shStrTabSectionHeaderOffset + 0x14,4)
    return[shStrTabSectionOffset,shStrTabSectionSize]

def getShStrTabList(fileBin,shStrTabSectionOffset,shStrTabSectionSize):
    chrList = []
    fileBin.seek(shStrTabSectionOffset)
    for i in range(shStrTabSectionSize):
        b = fileBin.read(1)
        n = binToInt(b)
        chrList.append(chr(n))
    return chrList

def getSectionNameFromNameIndex(chrList,sectionNameIndex):
    i = sectionNameIndex
    sectionName = ""
    while chrList[i] != '\x00':
        sectionName = sectionName + chrList[i]
        i = i + 1
    return sectionName

def getMemoryMsg(fileBin,programHeaderOffset,programNum):
    for programIndex in range(programNum):
        curProgramHeaderOffset = sectionHeaderOffset + programIndex * 0x20
        curType = getMsgFromBin(fileBin,curProgramHeaderOffset,4)
        curOffset = getMsgFromBin(fileBin,curProgramHeaderOffset+0x04,4)
        curVaddr = getMsgFromBin(fileBin,curProgramHeaderOffset+0x08,4)
        curPaddr = getMsgFromBin(fileBin,curProgramHeaderOffset+0x0C,4)
        curFileSz = getMsgFromBin(fileBin,curProgramHeaderOffset+0x10,4)
        curMemSz = getMsgFromBin(fileBin,curProgramHeaderOffset+0x14,4)
        curFlags = getMsgFromBin(fileBin,curProgramHeaderOffset+0x18,4)
        curAlign = getMsgFromBin(fileBin,curProgramHeaderOffset+0x1C,4)
        print([curType,hex(curOffset),hex(curVaddr),hex(curPaddr),curFileSz,curMemSz,curFlags,curAlign])
    return


def getTextMsg(fileBin,sectionHeaderOffset,sectionNum,chrList):
    textOffset = -1
    textSize = -1
    textAbsoluteAddr = -1
    for sectionIndex in range(sectionNum):
        curSectionHeaderOffset = sectionHeaderOffset + sectionIndex * 0x28
        curSectionNameIndex = getMsgFromBin(fileBin,curSectionHeaderOffset,4)
        curSectionName = getSectionNameFromNameIndex(chrList,curSectionNameIndex)
        if curSectionName == ".text":
            textAbsoluteAddr = getMsgFromBin(fileBin,curSectionHeaderOffset + 12,4)
            textOffset = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x10,4)
            textSize = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x14,4)
            break
    return [textOffset,textSize,textAbsoluteAddr - textOffset]

def getChangeSectionMsg(fileBin,sectionHeaderOffset,sectionNum,chrList,rodataOffset,bssOffset):

    changeSectionMsg = []
    for sectionIndex in range(sectionNum):
        curSectionHeaderOffset = sectionHeaderOffset + sectionIndex * 0x28
        curSectionNameIndex = getMsgFromBin(fileBin,curSectionHeaderOffset,4)
        curSectionName = getSectionNameFromNameIndex(chrList,curSectionNameIndex)
        textAbsoluteAddr = getMsgFromBin(fileBin,curSectionHeaderOffset + 12,4)
        textOffset = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x10,4)
        textSize = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x14,4)
        if textOffset >= rodataOffset and textOffset < bssOffset:
            changeSectionMsg.append([textOffset,textSize,textAbsoluteAddr-textOffset,curSectionName])
    return changeSectionMsg


def getSymTabMsg(fileBin,sectionHeaderOffset,sectionNum,chrList):
    textOffset = -1
    textSize = -1
    for sectionIndex in range(sectionNum):
        curSectionHeaderOffset = sectionHeaderOffset + sectionIndex * 0x28
        curSectionNameIndex = getMsgFromBin(fileBin,curSectionHeaderOffset,4)
        curSectionName = getSectionNameFromNameIndex(chrList,curSectionNameIndex)
        if curSectionName == ".symtab":
            textOffset = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x10,4)
            textSize = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x14,4)
            break
    return [textOffset,textSize]

def getBssMsg(fileBin,sectionHeaderOffset,sectionNum,chrList):
    textOffset = -1
    textSize = -1
    for sectionIndex in range(sectionNum):
        curSectionHeaderOffset = sectionHeaderOffset + sectionIndex * 0x28
        curSectionNameIndex = getMsgFromBin(fileBin,curSectionHeaderOffset,4)
        curSectionName = getSectionNameFromNameIndex(chrList,curSectionNameIndex)
        if curSectionName == ".bss":
            textOffset = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x10,4)
            textSize = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x14,4)
            break
    return [textOffset,textSize]

def getRodataMsg(fileBin,sectionHeaderOffset,sectionNum,chrList):
    textOffset = -1
    textSize = -1
    for sectionIndex in range(sectionNum):
        curSectionHeaderOffset = sectionHeaderOffset + sectionIndex * 0x28
        curSectionNameIndex = getMsgFromBin(fileBin,curSectionHeaderOffset,4)
        curSectionName = getSectionNameFromNameIndex(chrList,curSectionNameIndex)
        if curSectionName == ".rodata":
            textOffset = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x10,4)
            textSize = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x14,4)
            break
    return [textOffset,textSize]

def getStrTabMsg(fileBin,sectionHeaderOffset,sectionNum,chrList):
    textOffset = -1
    textSize = -1
    for sectionIndex in range(sectionNum):
        curSectionHeaderOffset = sectionHeaderOffset + sectionIndex * 0x28
        curSectionNameIndex = getMsgFromBin(fileBin,curSectionHeaderOffset,4)
        curSectionName = getSectionNameFromNameIndex(chrList,curSectionNameIndex)
        if curSectionName == ".strtab":
            textOffset = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x10,4)
            textSize = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x14,4)
            break
    return [textOffset,textSize]

def getInitMsg(fileBin,sectionHeaderOffset,sectionNum,chrList):
    textOffset = -1
    textSize = -1
    for sectionIndex in range(sectionNum):
        curSectionHeaderOffset = sectionHeaderOffset + sectionIndex * 0x28
        curSectionNameIndex = getMsgFromBin(fileBin,curSectionHeaderOffset,4)
        curSectionName = getSectionNameFromNameIndex(chrList,curSectionNameIndex)
        #print([curSectionName,hex(getMsgFromBin(fileBin,curSectionHeaderOffset + 0x10,4)+0x8000)])
        if curSectionName == ".init":
            textOffset = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x10,4)
            textSize = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x14,4)
            break
    return [textOffset,textSize]

def getFiniMsg(fileBin,sectionHeaderOffset,sectionNum,chrList):
    textOffset = -1
    textSize = -1
    for sectionIndex in range(sectionNum):
        curSectionHeaderOffset = sectionHeaderOffset + sectionIndex * 0x28
        curSectionNameIndex = getMsgFromBin(fileBin,curSectionHeaderOffset,4)
        curSectionName = getSectionNameFromNameIndex(chrList,curSectionNameIndex)
        if curSectionName == ".fini":
            textOffset = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x10,4)
            textSize = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x14,4)
            break
    return [textOffset,textSize]

def getAllSym(fileBin,symTabOffset,symTabSize,chrList):
    symMsg = []
    symNum = int(symTabSize/16)
    for symIndex in range(symNum):
        curSymOffset = symTabOffset + symIndex * 16
        curSymNameIndex = getMsgFromBin(fileBin,curSymOffset,4)
        curSymName = getSectionNameFromNameIndex(chrList,curSymNameIndex)
        curSymValue = getMsgFromBin(fileBin,curSymOffset + 4,4)
        curSymSize = getMsgFromBin(fileBin,curSymOffset + 8,4)
        symMsg.append([curSymName,hex(curSymValue),curSymSize])

    return symMsg

def readInstruction(fileBin):
    b1 = fileBin.read(1)
    b2 = fileBin.read(1)
    b3 = fileBin.read(1)
    b4 = fileBin.read(1)
    n1 = binToInt(b1)
    n2 = binToInt(b2)
    n3 = binToInt(b3)
    n4 = binToInt(b4)
    return from4BLittleEndian(n1,n2,n3,n4)

def readInstructionFromAddr(fileBin,addr):
    return getMsgFromBin(fileBin,addr,4)

def writeInstructionFromAddr(fileBin,addr,data):
    fileBin.seek(addr)
    [b1,b2,b3,b4] = getBinFromData(data,4)
    fileBin.write(b1)
    fileBin.write(b2)
    fileBin.write(b3)
    fileBin.write(b4)
    return 

def getLiteralMsg(fileBin,textOffset,textSize):
    ldr2Literal = {}
    literal2Ldr = {}
    literalFlag = {}
    fileBin.seek(textOffset)
    for index in range(0,textSize,4):
        instruction = readInstruction(fileBin)
        if instruction&0x0F7F0000 == 0x051F0000:
            literalPCOffset = instruction&0x00000FFF
            if instruction&0x00800000 == 0x00000000:
                literalPCOffset *= -1
            ldrOffset = textOffset + index
            literalOffset = ldrOffset + 8 + literalPCOffset                
            ldr2Literal[hex(ldrOffset)] = hex(literalOffset)
            if hex(literalOffset) in literal2Ldr.keys():
                literal2Ldr[hex(literalOffset)].append(hex(ldrOffset))
                if literalFlag[hex(literalOffset)] == 0 and literalPCOffset < 0:
                    literalFlag[hex(literalOffset)] = 2
                if literalFlag[hex(literalOffset)] == 1 and literalPCOffset > 0:
                    literalFlag[hex(literalOffset)] = 2  
            else:
                literal2Ldr[hex(literalOffset)] = [hex(ldrOffset)]
                literalFlag[hex(literalOffset)] = 0
                if literalPCOffset < 0:
                    literalFlag[hex(literalOffset)] = 1
                    
    return [ldr2Literal,literal2Ldr,literalFlag]

def testLiteralMsg(ldr2Literal,literal2Ldr):
    ls = []
    for (k,v) in ldr2Literal.items():
        if k in literal2Ldr.keys():
            ls.append([k,v])
    for [k,v] in ls:
        ldr2Literal.pop(k)
        literal2Ldr.pop(v)
    return

def getLiteralPoolMsg(textOffset,textSize,literal2Ldr,literalFlag):
    cnt = -1
    literalPoolMsg = []
    inPool = False
    for index in range(textOffset,textOffset + textSize,4):
        if hex(index) in literal2Ldr.keys():
            if inPool == False:
                cnt += 1
                inPool = True
                start = index
                literalPoolMsg.append([hex(start),1,literalFlag[hex(start)]])
            else:
                literalPoolMsg[cnt][1] += 1 
                if literalPoolMsg[cnt][2] == 0 and literalFlag[hex(index)] == 1:
                    literalPoolMsg[cnt][2] = 2
                if literalPoolMsg[cnt][2] == 1 and literalFlag[hex(index)] == 0:
                    literalPoolMsg[cnt][2] = 2
                if literalFlag[hex(index)] == 2:
                    literalPoolMsg[cnt][2] = 2
        else:
            inPool = False
    return literalPoolMsg

def getSpecialAMsg(literal2Ldr,imageBase,textOffset,textSize):
    switchTabMsg = {}
    specialAMsg = {}
    for index in range(textOffset,textOffset+textSize,4):
        instruction = readInstructionFromAddr(fileBin,index)
        if (instruction&0xFFFFFFF0 == 0x979FF100) and not(hex(index) in literal2Ldr.keys()):
            index += 8
            start = index
            switchTabMsg[hex(start)] = 0
            while not (hex(index+imageBase) in aMsg.keys()):
                index += 4
                switchTabMsg[hex(start)] += 1
            specialAMsg[hex(index+imageBase)] = 1
    return [specialAMsg,switchTabMsg]

def getCodeMsg(textOffset,textSize,aMsg,literalPoolMsg,imageBase,specialAMsg):
    codeMsg = []
    specialCode = {}
    literalPoolNum = len(literalPoolMsg)
    if literalPoolNum == 0 and textSize > 0 :
        codeMsg.append([hex(textOffset),textSize,-1])
    if literalPoolNum > 0 and int(literalPoolMsg[0][0],16) > textOffset:
        codeMsg.append([hex(textOffset),int((int(literalPoolMsg[0][0],16)-textOffset)/4),0])
    for i in range(0,literalPoolNum-1):
        start = int(literalPoolMsg[i][0],16) + literalPoolMsg[i][1]*4
        end = textOffset + textSize
        end = int(literalPoolMsg[i+1][0],16)
        size = int((end - start)/4)
        
        split = []
        for addr in range(start+4,end,4):
            if (hex(imageBase + addr) in aMsg.keys()) and not (hex(imageBase + addr) in specialAMsg.keys()):
                split.append(addr)
        codes = []
        s = start
        for sp in split:
            codes.append([hex(s),int((sp-s)/4),-1])
            s = sp
        codes.append([hex(s),int((end-s)/4),-1])
        if literalPoolMsg[i][2] == 1:
            codes[0][2] = i
        if literalPoolMsg[i+1][2] == 0:
            codes[len(codes)-1][2] = i+1
        elif literalPoolMsg[i+1][2] == 2:
            specialCode[len(codeMsg)+len(codes)-1] = 0
            codes[len(codes)-1][2] = i+1
        for item in codes:
            codeMsg.append(item)
    if literalPoolNum > 0 and int(literalPoolMsg[literalPoolNum-1][0],16) + literalPoolMsg[literalPoolNum-1][1]*4 < textOffset + textSize:
        start = int(literalPoolMsg[literalPoolNum-1][0],16) + literalPoolMsg[literalPoolNum-1][1]*4
        end = textOffset + textSize
        size = int((end - start)/4)
        codeMsg.append([hex(start),size,-1])
    return [codeMsg,specialCode]

def getAMsg(symMsg,textOffset,textSize,imageBase):
    aMsg = {}
    for item in symMsg:
        addr = int(item[1],16) - imageBase
        if item[0] != "$d" and addr >= textOffset and addr < textOffset + textSize:
            aMsg[item[1]] = int(item[1],16)
    return aMsg

def getDMsg(sysmMsg,textOffset,textSize,imageBase):
    dMsg = {}
    for item in symMsg:
        addr = int(item[1],16) - imageBase
        if item[0] != "$a" and addr >= textOffset + textSize:
            if item[1] in dMsg.keys() and dMsg[item[1]] > 0:
                continue
            else:
                dMsg[item[1]] = item[2]
    return dMsg

def getSpecialDMsg(dMsg,aMsg,changeSectionMsg,textOffset,textSize,imageBase):
    specialDMsg = {}
    for item in changeSectionMsg:
        start = item[0]
        end = item[0] + item[1]
        base = item[2]
        addr = start
        while addr < end:
            abAddr = base + addr
            if hex(abAddr) in dMsg.keys() and dMsg[hex(abAddr)] != 0 and dMsg[hex(abAddr)] % 4 == 0:
                record = abAddr
                cnt = 0
                cntAll = 0
                for i in range(int(dMsg[hex(abAddr)]/4)):
                    literal = readInstructionFromAddr(fileBin,addr)
                    destAddr = literal - imageBase
                    if literal != 0:
                        cntAll += 1
                    if hex(literal) in aMsg.keys() and destAddr >= textOffset and destAddr < textOffset + textSize:
                        cnt += 1
                    addr += 4  
                if cnt >= cntAll/25 or dMsg[hex(abAddr)]/4 < 100:  #数值越小，不改的就越多，就容易有gem5运行错误
                    specialDMsg[hex(record)] = dMsg[hex(record)]
            else:
                addr +=4
    return specialDMsg


def writeBlock(blockOffset,blockSize):
    bo = int(blockOffset,16)
    fileBin.seek(bo)
    b = fileBin.read(blockSize)
    fileOut.write(b)
    return

'''
def getFisrtLdr(codeMsg,ldr2Literal):
    codeFirstLdrOffset = []
    for code in codeMsg:
        isFind = False
        for off in range(code[1]):
            actualOffset = int(code[0],16) + off*4
            if hex(actualOffset) in ldr2Literal.keys():
                codeFirstLdrOffset.append(off)
                isFind = True
                break
        if isFind == False:
            codeFirstLdrOffset.append(-1)
    return codeFirstLdrOffset
 ''' 
def judgeInWhitchCode(codeMsg,addr):
    for i in range(len(codeMsg) - 1):
        if int(addr,16) >= int(codeMsg[i][0],16) and int(addr,16) < int(codeMsg[i][0],16) + codeMsg[i][1]*4:
            return [codeMsg[i][0],int((int(addr,16) - int(codeMsg[i][0],16))/4)]
    return [codeMsg[len(codeMsg)-1][0],int((int(addr,16) - int(codeMsg[len(codeMsg)-1][0],16))/4)]


def writeLiteralPool(recordCode,endCode):
    if recordCode == endCode:
        return
    for code in range(recordCode,endCode):
        targetLiteralPool = codeMsg[code][2]
        if targetLiteralPool == -1:
            continue
        else:
            outPoint = fileOut.tell()
            outLiteralPoolMsg[targetLiteralPool] = [hex(outPoint),literalPoolMsg[targetLiteralPool][1]]
            writeBlock(literalPoolMsg[targetLiteralPool][0],literalPoolMsg[targetLiteralPool][1]*4)
            #outPoint += literalPoolMsg[targetLiteralPool][1]*4
    return

def writeCode(code):
    outPoint = fileOut.tell()
    outCodeMsg[code] = [hex(outPoint),codeMsg[code][1]]
    writeBlock(codeMsg[code][0],codeMsg[code][1]*4)
    #outPoint += codeMsg[code][1]*4
    return

def relocate():
    curCode = 0
    recordCode = 0
    codeSum = 0
    codeNum = len(codeMsg)
    while curCode < codeNum:
        if not (curCode in specialCode.keys()):
            if codeSum + codeMsg[curCode][1] <= 1024:
                codeSum += codeMsg[curCode][1]
                writeCode(curCode)
                curCode += 1
            elif codeMsg[curCode][1] > 1024 and codeSum == 0:
                writeCode(curCode)
                writeLiteralPool(curCode,curCode+1)
                curCode += 1
                recordCode = curCode
            else:
                writeLiteralPool(recordCode,curCode)
                recordCode = curCode
                codeSum = 0
        else:
            writeLiteralPool(recordCode,curCode)
            writeCode(curCode)
            writeLiteralPool(curCode,curCode+1)
            curCode += 1
            codeSum = 0
            recordCode = curCode
    writeLiteralPool(recordCode,curCode)
    return

def findCodeLocation(codeMsg,addr):
    codeNum = len(codeMsg)
    for index in range(1,codeNum):
        if int(addr,16) < int(codeMsg[index][0],16):
            return [index-1,int((int(addr,16) - int(codeMsg[index-1][0],16))/4)]
    return [codeNum-1,int((int(addr,16) - int(codeMsg[codeNum-1][0],16))/4)]

def findLiteralLocation(literalPoolMsg,addr):
    poolNum = len(literalPoolMsg)
    for index in range(1,poolNum):
        if int(addr,16) < int(literalPoolMsg[index][0],16):
            return [index-1,int((int(addr,16) - int(literalPoolMsg[index-1][0],16))/4)]
    return [poolNum-1,int((int(addr,16) - int(literalPoolMsg[poolNum-1][0],16))/4)]

def resetBInstruction(codeMsg,outCodeMsg,textOffset,textSize,switchTabMsg):
    codeNum = len(codeMsg)
    for codeIndex in range(codeNum):
        codeBase = int(codeMsg[codeIndex][0],16)
        for codeOff in range(codeMsg[codeIndex][1]):
            instructionAddr = codeBase + codeOff*4
            if hex(instructionAddr) in switchTabMsg.keys():
                codeOff += switchTabMsg[hex(instructionAddr)]
                continue
            instruction = readInstructionFromAddr(fileBin,instructionAddr)
            if instruction&0x0E000000 == 0x0A000000:
                off = instruction&0x00FFFFFF
                if off&0x00800000 == 0x00800000:
                    off = off - pow(2,24)
                destAddr = instructionAddr + 8 + off*4
                outDestAddr = destAddr
                if destAddr >= textOffset and destAddr < textOffset + textSize:
                    [destCodeIndex,destCodeOffset] = findCodeLocation(codeMsg,hex(destAddr))
                    outDestAddr = int(outCodeMsg[destCodeIndex][0],16) + destCodeOffset*4
                outCodeBase = outCodeMsg[codeIndex][0]
                outCodeOff = codeOff
                outInstructionAddr = int(outCodeBase,16) + outCodeOff*4
                outOff = int((outDestAddr - outInstructionAddr - 8)/4)
                if outOff < 0:
                    outOff = outOff + pow(2,24)
                outInstruction = (instruction&0xFF000000) + outOff
                writeInstructionFromAddr(fileOut,outInstructionAddr,outInstruction)
    return

def resetOtherSection(codeMsg,outCodeMsg,literalPoolMsg,outLiteralPoolMsg,otherCodeMsg,otherLiteralPoolMsg,textOffset,textSize,switchTabMsg):
    codeNum = len(otherCodeMsg)
    for codeIndex in range(codeNum):
        codeBase = int(otherCodeMsg[codeIndex][0],16)
        for codeOff in range(otherCodeMsg[codeIndex][1]):
            instructionAddr = codeBase + codeOff*4
            if hex(instructionAddr) in switchTabMsg.keys():
                codeOff += switchTabMsg[hex(instructionAddr)]
                continue
            instruction = readInstructionFromAddr(fileBin,instructionAddr)
            if instruction&0x0E000000 == 0x0A000000: #B
                off = instruction&0x00FFFFFF
                if off&0x00800000 == 0x00800000:
                    off = off - pow(2,24)
                destAddr = instructionAddr + 8 + off*4
                if destAddr >= textOffset and destAddr < textOffset + textSize:
                    [destCodeIndex,destCodeOffset] = findCodeLocation(codeMsg,hex(destAddr))
                    outInstructionAddr = instructionAddr
                    outDestAddr = int(outCodeMsg[destCodeIndex][0],16) + destCodeOffset*4
                    outOff = int((outDestAddr - outInstructionAddr - 8)/4)
                    if outOff < 0:
                        outOff = outOff + pow(2,24)
                    outInstruction = (instruction&0xFF000000) + outOff
                    writeInstructionFromAddr(fileOut,outInstructionAddr,outInstruction)
                    
    poolNum = len(otherLiteralPoolMsg)
    for poolIndex in range(poolNum):
        poolBase = int(otherLiteralPoolMsg[poolIndex][0],16)
        for poolOff in range(otherLiteralPoolMsg[poolIndex][1]):
            literalAddr = poolBase + poolOff*4
            literal = readInstructionFromAddr(fileBin,literalAddr)
            if hex(literal) in aMsg.keys():
                destAddr = literal - imageBase
                if destAddr >= textOffset and destAddr < textOffset + textSize:
                    [destCodeIndex,destCodeOffset] = findCodeLocation(codeMsg,hex(destAddr))
                    outDestAddr = int(outCodeMsg[destCodeIndex][0],16) + destCodeOffset*4
                    outLiteralAddr = literalAddr
                    outLiteral = outDestAddr + imageBase
                    writeInstructionFromAddr(fileOut,outLiteralAddr,outLiteral)  
    return

def resetLdrInstruction(otherCodeMsg,outCodeMsg,literalPoolMsg,outLiteralPoolMsg,switchTabMsg):
    codeNum = len(codeMsg)
    for codeIndex in range(codeNum):
        codeBase = int(codeMsg[codeIndex][0],16)
        for codeOff in range(codeMsg[codeIndex][1]):
            instructionAddr = codeBase + codeOff*4
            if hex(instructionAddr) in switchTabMsg.keys():
                codeOff += switchTabMsg[hex(instructionAddr)]
                continue
            instruction = readInstructionFromAddr(fileBin,instructionAddr)
            if instruction&0x0F7F0000 == 0x051F0000:
                off = instruction&0x00000FFF
                if (instruction&0x00800000) == 0x00000000:
                    off *= -1
                destAddr = instructionAddr + 8 + off
                
                [destPoolIndex,destPoolOffset] = findLiteralLocation(literalPoolMsg,hex(destAddr))
                
                outCodeBase = outCodeMsg[codeIndex][0]
                outCodeOff = codeOff
                outInstructionAddr = int(outCodeBase,16) + outCodeOff*4
                outDestAddr = int(outLiteralPoolMsg[destPoolIndex][0],16) + destPoolOffset*4
                
                outOff = outDestAddr - outInstructionAddr - 8
                
                outInstruction = instruction&0xFF7FF000
                if outOff < 0:
                    outOff *= -1
                else:
                    outInstruction += 0x00800000
                outInstruction += outOff
                writeInstructionFromAddr(fileOut,outInstructionAddr,outInstruction)    
    return


def resetLiteralAddress(literalPoolMsg,outLiteralPoolMsg,codeMsg,outCodeMsg,imageBase,textOffset,textSize):
    poolNum = len(literalPoolMsg)
    for poolIndex in range(poolNum):
        poolBase = int(literalPoolMsg[poolIndex][0],16)
        for poolOff in range(literalPoolMsg[poolIndex][1]):
            literalAddr = poolBase + poolOff*4
            literal = readInstructionFromAddr(fileBin,literalAddr)
            if hex(literal) in aMsg.keys():
                destAddr = literal - imageBase
                if destAddr >= textOffset and destAddr < textOffset + textSize:
                    [destCodeIndex,destCodeOffset] = findCodeLocation(codeMsg,hex(destAddr))
                    outDestAddr = int(outCodeMsg[destCodeIndex][0],16) + destCodeOffset*4
                    outLiteralAddr = int(outLiteralPoolMsg[poolIndex][0],16) + poolOff*4
                    outLiteral = outDestAddr + imageBase
                    writeInstructionFromAddr(fileOut,outLiteralAddr,outLiteral)           
    return

def resetChangeSection(changeSectionMsg,aMsg,dMsg,codeMsg,outCodeMsg,imageBase,textOffset,textSize,specialDMsg):
    for item in changeSectionMsg:
        start = item[0]
        end = item[0] + item[1]
        base = item[2]
        addr = start
        print("please check absolute address following:")
        while addr < end:
            abAddr = base + addr
            if hex(abAddr) in dMsg.keys() and dMsg[hex(abAddr)] != 0 and dMsg[hex(abAddr)] % 4 == 0:
                if not(hex(abAddr) in specialDMsg.keys()):
                    for i in range(int(dMsg[hex(abAddr)]/4)):
                        literal = readInstructionFromAddr(fileBin,addr)
                        if hex(literal) in aMsg.keys():
                            destAddr = literal - imageBase
                            if destAddr >= textOffset and destAddr < textOffset + textSize:
                                print(str(int(dMsg[hex(abAddr)]/4)) + "  " + hex(addr+base))     
                        addr += 4
                    continue
                for i in range(int(dMsg[hex(abAddr)]/4)):
                    literal = readInstructionFromAddr(fileBin,addr)
                    if hex(literal) in aMsg.keys():
                        destAddr = literal - imageBase
                        if destAddr >= textOffset and destAddr < textOffset + textSize:
                            [destCodeIndex,destCodeOffset] = findCodeLocation(codeMsg,hex(destAddr))
                            outDestAddr = int(outCodeMsg[destCodeIndex][0],16) + destCodeOffset*4
                            outAddr = addr
                            outLiteral = outDestAddr + imageBase
                            writeInstructionFromAddr(fileOut,outAddr,outLiteral)  
                            #print(hex(abAddr))
                    addr += 4
            elif hex(abAddr) in dMsg.keys() and dMsg[hex(abAddr)] == 0:
                literal = readInstructionFromAddr(fileBin,addr)
                if hex(literal) in aMsg.keys():
                    destAddr = literal - imageBase
                    if destAddr >= textOffset and destAddr < textOffset + textSize:
                        [destCodeIndex,destCodeOffset] = findCodeLocation(codeMsg,hex(destAddr))
                        outDestAddr = int(outCodeMsg[destCodeIndex][0],16) + destCodeOffset*4
                        outAddr = addr
                        outLiteral = outDestAddr + imageBase
                        writeInstructionFromAddr(fileOut,outAddr,outLiteral)  
                addr += 4
            else:
                addr +=4
    return

def findLastLdr(codeMsg,literalPoolMsg,codeIndex,instructionOffset,register):
    curOffset = instructionOffset-1
    while curOffset >= 0:
        curAddr = int(codeMsg[codeIndex][0],16) + curOffset*4
        curData = readInstructionFromAddr(fileBin,curAddr)
        if (curData&0x0F7F0000) == 0x051F0000 and ((curData&0x0000F000)>>12) == register:
            off = curData&0x00000FFF
            if (curData&0x00800000) == 0x00000000:
                off *= -1
            destAddr = curAddr + 8 + off  
            rData = readInstructionFromAddr(fileBin,destAddr)
            [destPoolIndex,destPoolOffset] = findLiteralLocation(literalPoolMsg,hex(destAddr))
            outLiteralAddr = int(outLiteralPoolMsg[destPoolIndex][0],16) + destPoolOffset*4
            return [rData,outLiteralAddr]
        curOffset -= 1
    return [-1,-1]

def resetLdrRLiteral(codeMsg,literalPoolMsg,switchTabMsg):
    codeNum = len(codeMsg)
    for codeIndex in range(codeNum):
        codeBase = int(codeMsg[codeIndex][0],16)
        codeSize = codeMsg[codeIndex][1]
        for instructionOffset in range(codeSize):
            instructionAddr = codeBase + instructionOffset*4
            if hex(instructionAddr) in switchTabMsg.keys():
                instructionOffset += switchTabMsg[hex(instructionAddr)]
                continue
            instruction = readInstructionFromAddr(fileBin,instructionAddr)
            if ((instruction&0x0F7F0000) == 0x071F0000) and ((instruction&0x0000F000) != 0x0000F000):
                register = instruction&0x0000000F
                [rData,outLiteralAddr] = findLastLdr(codeMsg,literalPoolMsg,codeIndex,instructionOffset,register)
                if rData == -1 and outLiteralAddr == -1:
                    continue
                if (instruction&0x00800000) == 0x00000000:
                    rData *= -1
                outCodeBase = outCodeMsg[codeIndex][0]
                outInstructionAddr = int(outCodeBase,16) + instructionOffset*4
                outDestAddr = instructionAddr + 8 + rData
                outRData = outDestAddr - outInstructionAddr - 8
                writeInstructionFromAddr(fileOut,outLiteralAddr,outRData) 
    return

def resetAddRLiteral(codeMsg,literalPoolMsg,switchTabMsg):
    codeNum = len(codeMsg)
    for codeIndex in range(codeNum):
        codeBase = int(codeMsg[codeIndex][0],16)
        codeSize = codeMsg[codeIndex][1]
        for instructionOffset in range(codeSize):
            instructionAddr = codeBase + instructionOffset*4
            if hex(instructionAddr) in switchTabMsg.keys():
                instructionOffset += switchTabMsg[hex(instructionAddr)]
                continue
            instruction = readInstructionFromAddr(fileBin,instructionAddr)
            if (instruction&0x0FFF0FF0) == 0x008F0000 and (instruction&0x0000F000) != 0x0000F000:
                register = instruction&0x0000000F
                [rData,outLiteralAddr] = findLastLdr(codeMsg,literalPoolMsg,codeIndex,instructionOffset,register)
                if rData == -1 and outLiteralAddr == -1:
                    continue
                outCodeBase = outCodeMsg[codeIndex][0]
                outInstructionAddr = int(outCodeBase,16) + instructionOffset*4
                outDestAddr = instructionAddr + 8 + rData
                outRData = outDestAddr - outInstructionAddr - 8
                writeInstructionFromAddr(fileOut,outLiteralAddr,outRData) 
    return

def resetSwitchTable(codeMsg,outCodeMsg,imageBase,textOffset,textSize):
    codeNum = len(codeMsg)
    for codeIndex in range(codeNum):
        codeBase = int(codeMsg[codeIndex][0],16)
        for codeOff in range(codeMsg[codeIndex][1]):
            instructionAddr = codeBase + codeOff*4
            instruction = readInstructionFromAddr(fileBin,instructionAddr)
            if instruction&0xFFFFFFF0 == 0x979FF100:
                literalAddr = instructionAddr + 8
                while not (hex(literalAddr+imageBase) in aMsg.keys()):
                    literal = readInstructionFromAddr(fileBin,literalAddr)
                    destAddr = literal - imageBase
                    if destAddr >= textOffset and destAddr < textOffset + textSize:
                        [destCodeIndex,destCodeOffset] = findCodeLocation(codeMsg,hex(destAddr))
                        outDestAddr = int(outCodeMsg[destCodeIndex][0],16) + destCodeOffset*4
                        outLiteralAddr = int(outCodeMsg[codeIndex][0],16) + literalAddr - codeBase
                        outLiteral = outDestAddr + imageBase
                        writeInstructionFromAddr(fileOut,outLiteralAddr,outLiteral)                       
                    literalAddr += 4
                codeOff = int((literalAddr - codeBase) / 4)
    return
def resetSymTab(fileBin,fileOut,symTabOffset,symTabSize,textOffset,textSize,imageBase,codeMsg,outCodeMsg,literalPoolMsg,outLiteralPoolMsg,switchTabMsg,chrList):
    symNum = int(symTabSize/16)
    for symIndex in range(symNum):
        curSymOffset = symTabOffset + symIndex * 16
        curSymNameIndex = getMsgFromBin(fileBin,curSymOffset,4)
        curSymName = getSectionNameFromNameIndex(chrList,curSymNameIndex)
        curSymValue = getMsgFromBin(fileBin,curSymOffset + 4,4)
        if curSymValue >= textOffset + imageBase and curSymValue < textOffset + textSize + imageBase:
            if curSymName != '$d' or hex(curSymValue-imageBase) in switchTabMsg.keys():
                [destCodeIndex,destCodeOffset] = findCodeLocation(codeMsg,hex(curSymValue-imageBase))
                outDestAddr = int(outCodeMsg[destCodeIndex][0],16) + destCodeOffset*4
                writeInstructionFromAddr(fileOut,curSymOffset + 4,outDestAddr+imageBase)
            else:
                [destPoolIndex,destPoolOffset] = findLiteralLocation(literalPoolMsg,hex(curSymValue-imageBase))
                outLiteralAddr = int(outLiteralPoolMsg[destPoolIndex][0],16) + destPoolOffset*4
                writeInstructionFromAddr(fileOut,curSymOffset + 4,outLiteralAddr+imageBase)
    return

    

pathBin = "./inBin"
pathOut = "./outBin"
fileBin = open(pathBin,"rb")
fileOut = open(pathOut,"wb")

[sectionHeaderOffset,sectionNum,shStrTabIndex] = getSectionMsg(fileBin)
[programHeaderOffset,programNum] = getProgramMsg(fileBin)

[shStrTabSectionOffset,shStrTabSectionSize] = getShStrTabMsg(fileBin,sectionHeaderOffset,shStrTabIndex)
shStrTabList = getShStrTabList(fileBin,shStrTabSectionOffset,shStrTabSectionSize)
[textOffset,textSize,imageBase] = getTextMsg(fileBin,sectionHeaderOffset,sectionNum,shStrTabList)
[initOffset,initSize] = getInitMsg(fileBin,sectionHeaderOffset,sectionNum,shStrTabList)
[finiOffset,finiSize] = getFiniMsg(fileBin,sectionHeaderOffset,sectionNum,shStrTabList)


[rodataOffset,rodataSize] = getRodataMsg(fileBin,sectionHeaderOffset,sectionNum,shStrTabList)
[bssOffset,bssSize] = getBssMsg(fileBin,sectionHeaderOffset,sectionNum,shStrTabList)

changeSectionMsg = getChangeSectionMsg(fileBin,sectionHeaderOffset,sectionNum,shStrTabList,rodataOffset,bssOffset)



beforeOffset = initOffset
beforeSize = initSize
afterOffset = textOffset + textSize
afterSize = finiOffset+finiSize-afterOffset
[strTabOffset,strTabSize] = getStrTabMsg(fileBin,sectionHeaderOffset,sectionNum,shStrTabList)
[symTabOffset,symTabSize] = getSymTabMsg(fileBin,sectionHeaderOffset,sectionNum,shStrTabList)
strTabList = getShStrTabList(fileBin,strTabOffset,strTabSize)
symMsg = getAllSym(fileBin,symTabOffset,symTabSize,strTabList)

out = open("./out.txt","wt")
out.write(str(symMsg))
out.close()

aMsg = getAMsg(symMsg,textOffset,textSize,imageBase)
dMsg = getDMsg(symMsg,textOffset,textSize,imageBase)
specialDMsg = getSpecialDMsg(dMsg,aMsg,changeSectionMsg,textOffset,textSize,imageBase)

'''
for item in symMsg:
    if item[1] == "0xb230":
        print(item)
'''


[ldr2Literal,literal2Ldr,literalFlag] = getLiteralMsg(fileBin,textOffset,textSize)
testLiteralMsg(ldr2Literal,literal2Ldr)
literalPoolMsg = getLiteralPoolMsg(textOffset,textSize,literal2Ldr,literalFlag)
[specialAMsg,switchTabMsg] = getSpecialAMsg(literal2Ldr,imageBase,textOffset,textSize)
[codeMsg,specialCode] = getCodeMsg(textOffset,textSize,aMsg,literalPoolMsg,imageBase,specialAMsg)

[beforeLdr2Literal,beforeLiteral2Ldr,beforeLiteralFlag] = getLiteralMsg(fileBin,beforeOffset,beforeSize)
testLiteralMsg(beforeLdr2Literal,beforeLiteral2Ldr)
beforeLiteralPoolMsg = getLiteralPoolMsg(beforeOffset,beforeSize,beforeLiteral2Ldr,beforeLiteralFlag)
[beforeSpecialAMsg,beforeSwitchTabMsg] = getSpecialAMsg(beforeLiteral2Ldr,imageBase,beforeOffset,beforeSize)
[beforeCodeMsg,beforeSpecialCode] = getCodeMsg(beforeOffset,beforeSize,aMsg,beforeLiteralPoolMsg,imageBase,beforeSpecialAMsg)

[afterLdr2Literal,afterLiteral2Ldr,afterLiteralFlag] = getLiteralMsg(fileBin,afterOffset,afterSize)
testLiteralMsg(afterLdr2Literal,afterLiteral2Ldr)
afterLiteralPoolMsg = getLiteralPoolMsg(afterOffset,afterSize,afterLiteral2Ldr,afterLiteralFlag)
[afterSpecialAMsg,afterSwitchTabMsg] = getSpecialAMsg(afterLiteral2Ldr,imageBase,afterOffset,afterSize)
[afterCodeMsg,afterSpecialCode] = getCodeMsg(afterOffset,afterSize,aMsg,afterLiteralPoolMsg,imageBase,afterSpecialAMsg)

otherCodeMsg = beforeCodeMsg+afterCodeMsg
otherSpecialCode = {**beforeSpecialCode, **afterSpecialCode} 
otherSwitchTabMsg = {**beforeSwitchTabMsg, **afterSwitchTabMsg} 
#otherSpecialCode = beforeSpecialCode + afterSpecialCode
otherLiteralPoolMsg = beforeLiteralPoolMsg + afterLiteralPoolMsg

writeBlock(hex(0),os.path.getsize(pathBin))
fileOut.seek(textOffset)
outCodeMsg = {}
outLiteralPoolMsg = {}
#outPoint = textOffset
relocate()
resetBInstruction(codeMsg,outCodeMsg,textOffset,textSize,switchTabMsg)
resetLiteralAddress(literalPoolMsg,outLiteralPoolMsg,codeMsg,outCodeMsg,imageBase,textOffset,textSize)
resetLdrInstruction(codeMsg,outCodeMsg,literalPoolMsg,outLiteralPoolMsg,switchTabMsg)
resetOtherSection(codeMsg,outCodeMsg,literalPoolMsg,outLiteralPoolMsg,otherCodeMsg,otherLiteralPoolMsg,textOffset,textSize,otherSwitchTabMsg)
resetChangeSection(changeSectionMsg,aMsg,dMsg,codeMsg,outCodeMsg,imageBase,textOffset,textSize,specialDMsg)
resetLdrRLiteral(codeMsg,literalPoolMsg,switchTabMsg)
resetAddRLiteral(codeMsg,literalPoolMsg,switchTabMsg)
resetSwitchTable(codeMsg,outCodeMsg,imageBase,textOffset,textSize)
resetSymTab(fileBin,fileOut,symTabOffset,symTabSize,textOffset,textSize,imageBase,codeMsg,outCodeMsg,literalPoolMsg,outLiteralPoolMsg,switchTabMsg,strTabList)
'''
import numpy as np

temp = np.zeros(len(literalPoolMsg),int)

for item in outLiteralPoolMsg.items():
    temp[item[0]] = 1

for i in range(temp.size):
    if temp[i] == 0:
        print(i)
'''
#getMemoryMsg(fileBin,programHeaderOffset,programNum)
fileBin.close()
fileOut.close()
