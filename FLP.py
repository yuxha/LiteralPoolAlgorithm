# -*- coding: UTF-8 -*-
import struct
import numpy as np
import matplotlib.pyplot as plt

def from2BLittleEndian(n1,n2):
    return (n2<<8)+n1

def from4BLittleEndian(n1,n2,n3,n4):
    return (n4<<24)+(n3<<16)+(n2<<8)+(n1)

def binToInt(dataBin):
    dataTuple = struct.unpack('B',dataBin)
    return dataTuple[0]

def getMsgFromBin(fileBin,offset,size): #get x Bytes' data from the binary file.
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

def getSectionMsg(fileBin): #get section messages in the ELF file.
    sectionHeaderOffset = getMsgFromBin(fileBin,0x20,4)
    sectionNum = getMsgFromBin(fileBin,0x30,2)
    shStrTabIndex = getMsgFromBin(fileBin,0x32,2)
    return [sectionHeaderOffset,sectionNum,shStrTabIndex]
    
def getShStrTabMsg(fileBin,sectionHeaderOffset,shStrTabIndex): #get messages about the shStr table 
    shStrTabSectionHeaderOffset = sectionHeaderOffset + shStrTabIndex * 0x28
    shStrTabSectionOffset = getMsgFromBin(fileBin,shStrTabSectionHeaderOffset + 0x10,4)
    shStrTabSectionSize = getMsgFromBin(fileBin,shStrTabSectionHeaderOffset + 0x14,4)
    return[shStrTabSectionOffset,shStrTabSectionSize]

def getShStrTabList(chrList,fileBin,shStrTabSectionOffset,shStrTabSectionSize): #get shStr List
    fileBin.seek(shStrTabSectionOffset)
    for i in range(shStrTabSectionSize):
        b = fileBin.read(1)
        n = binToInt(b)
        chrList.append(chr(n))
    return

def getSectionNameFromNameIndex(chrList,sectionNameIndex): #get section name from section name index
    i = sectionNameIndex
    sectionName = ""
    while chrList[i] != '\x00':
        sectionName = sectionName + chrList[i]
        i = i + 1
    return sectionName

def getTextMsg(fileBin,sectionHeaderOffset,sectionNum,chrList):
    textOffset = -1
    textSize = -1
    for sectionIndex in range(sectionNum):
        curSectionHeaderOffset = sectionHeaderOffset + sectionIndex * 0x28
        curSectionNameIndex = getMsgFromBin(fileBin,curSectionHeaderOffset,4)
        curSectionName = getSectionNameFromNameIndex(chrList,curSectionNameIndex)
        if curSectionName == ".text":
            textOffset = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x10,4)
            textSize = getMsgFromBin(fileBin,curSectionHeaderOffset + 0x14,4)
            break
    return [textOffset,textSize]

class LiteralMsg:
    ldrOffset = -1
    literalOffset = -1
    def __init__(self,ldrOffset,literalOffset):
        self.ldrOffset = ldrOffset
        self.literalOffset = literalOffset

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

def getLiteralMsg(fileBin,textOffset,textSize):
    ldr2Literal = {}
    literal2Ldr = {}
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
            else:
                literal2Ldr[hex(literalOffset)] = [hex(ldrOffset)]
    return [ldr2Literal,literal2Ldr]

def testLiteralMsg(ldr2Literal,literal2Ldr):
    ls = []
    for (k,v) in ldr2Literal.items():
        if k in literal2Ldr.keys():
            ls.append([k,v])
    for [k,v] in ls:
        ldr2Literal.pop(k)
        literal2Ldr.pop(v)
    return

def getLiteralPool(textOffset,textSize,literal2Ldr):
    literalPoolMsg = {}
    inPool = False
    for index in range(textOffset,textOffset + textSize,4):
        if hex(index) in literal2Ldr.keys():
            if inPool == False:
                inPool = True
                start = index
                literalPoolMsg[hex(start)] = 1
            else:
                literalPoolMsg[hex(start)] = literalPoolMsg[hex(start)] + 1 
        else:
            inPool = False
    return literalPoolMsg

def getBlockMsg(textOffset,textSize,literal2Ldr,ldr2Literal):
    blockMsg = {}
    for index in range(textOffset,textOffset + textSize,4):
        blockMsg[hex(index&I_CACHE_MASK)] = [0,0]
    for index in range(textOffset,textOffset + textSize,4):
        if hex(index) in literal2Ldr.keys():
            blockMsg[hex(index&I_CACHE_MASK)][1] = blockMsg[hex(index&I_CACHE_MASK)][1] + 1
        if hex(index) in ldr2Literal.keys():
            blockMsg[hex(index&I_CACHE_MASK)][0] = blockMsg[hex(index&I_CACHE_MASK)][0] + 1
    return blockMsg

def getLiteralPoolSizeDistribution(literalPoolMsg):
    maxSize = 0
    sumNum = 0
    for item in literalPoolMsg.items():
        poolSize = item[1]
        sumNum = sumNum + 1
        maxSize = max(maxSize,poolSize)
    y = np.zeros(maxSize,float)
    for item in literalPoolMsg.items():
        poolSize = item[1]
        y[poolSize-1] = y[poolSize-1] + 1
    y = (y/sumNum)*100
    x = np.array(range(1,maxSize+1))
    return [x,y]


def getLiteralInBlockDistribution(literalBlockMsg): 
    maxSize = int(I_CACHE_SIZE/4)
    x = np.array(range(0,maxSize+1))
    y = np.zeros(maxSize+1,int)
    for item in literalBlockMsg.items():
        literalSize = item[1][1]
        y[literalSize] = y[literalSize] + 1
    blockNum = len(literalBlockMsg)
    y = (y / blockNum) * 100
    return [x[1:],y[1:]]




def getDistanceBetweenLdrAndLiteral(ldr2Literal):
    ls = []
    maxDis = 0
    for (k,v) in ldr2Literal.items():
        dis = (int(v,16)&I_CACHE_MASK) - (int(k,16)&I_CACHE_MASK)
        ls.append(abs(int(dis/I_CACHE_SIZE)))
        maxDis = max(maxDis,abs(int(dis/I_CACHE_SIZE)))
    x = np.array(range(maxDis+1))
    y = np.zeros(maxDis+1,int)
    for item in ls:
        y[item] = y[item] + 1
    y = 100*y/len(ls)
    return [x,y]


def printDataByNp(file,x,y):
    file.write(str(x.size)+'\n')
    for d in x:
        file.write(str(d)+'\n')
    for d in y:
        file.write(str(d)+'\n')
    return

I_CACHE_SIZE = 64
D_CACHE_SIZE = 64
I_CACHE_MASK = 0xFFFFFFC0
D_CACHE_MASK = 0xFFFFFFC0

import os
path = "./"
elfNames = []
for file in os.listdir(path):  
    index = file.find(".in")
    if index != -1:
        elfNames.append(file[0:index])
elfFiles = []
for elfName in elfNames:
    file = open(elfName+".in","rb")
    elfFiles.append(file)
    
colors = ['r','y','g','c','b','m','orange','olive','navy','pink','peru']


def getMsg(fileBin):
    '''
    path1 = "./lps"+add+'.txt'
    path2 = "./lib"+add+'.txt'
    path3 = "./dis"+add+'.txt'
    fileLPSize = open(path1,"wt")
    fileLIB = open(path2,"wt")
    fileDistance = open(path3,"wt")
    '''
    [sectionHeaderOffset,sectionNum,shStrTabIndex] = getSectionMsg(fileBin)
    [shStrTabSectionOffset,shStrTabSectionSize] = getShStrTabMsg(fileBin,sectionHeaderOffset,shStrTabIndex)
    chrList = []
    getShStrTabList(chrList,fileBin,shStrTabSectionOffset,shStrTabSectionSize)
    [textOffset,textSize] = getTextMsg(fileBin,sectionHeaderOffset,sectionNum,chrList)
    [ldr2Literal,literal2Ldr] = getLiteralMsg(fileBin,textOffset,textSize)
    testLiteralMsg(ldr2Literal,literal2Ldr)
    literalPoolMsg = getLiteralPool(textOffset,textSize,literal2Ldr)
    literalBlockMsg = getBlockMsg(textOffset,textSize,literal2Ldr,ldr2Literal)   
    [xLPS,yLPS] = getLiteralPoolSizeDistribution(literalPoolMsg)
    [xLIB,yLIB] = getLiteralInBlockDistribution(literalBlockMsg)
    [xD,yD] = getDistanceBetweenLdrAndLiteral(ldr2Literal)
    '''
    printDataByNp(fileLPSize,xLPS,yLPS)
    printDataByNp(fileLIB,xLIB,yLIB)
    printDataByNp(fileDistance,xD,yD)
    fileLPSize.close()
    fileLIB.close()
    fileDistance.close()
    '''
    return [xLPS,yLPS,xLIB,yLIB,xD,yD]

def drawFig(pointList,elfNames,figPath):
    plt.figure(figsize = (12,6))
    plt.subplot(111)
    plt.grid()
    xLocator = plt.MultipleLocator(1)
    yLocator = plt.MultipleLocator(5)
    a = plt.gca()
    a.xaxis.set_major_locator(xLocator)
    a.yaxis.set_major_locator(yLocator)
    length = len(pointList)
    width = 0.8/length
    if length%2 == 0:
        begin = -1*(length/2)*width+width/2
    else:
        begin = -1*((length-1)/2)*width
    for index in range(length):
        x = pointList[index][0]
        y = pointList[index][1]
        plt.bar(x + begin + index * width, y, width, align='center', label=elfNames[index], color=colors[index])
    plt.xlim(0,25)
    plt.xlabel("Literal Pool Size (Word)",fontsize=20)
    plt.ylabel("Proportion of These Literal Pools (%)",fontsize=20)
    plt.title("Distribution of Literal Pool Sizes",fontsize=20)
    plt.legend(prop = {'size':12})
    plt.tick_params(labelsize=20)
    plt.savefig(figPath,dpi=500,bbox_inches = 'tight')
    return

pointList = []
for file in elfFiles:
    [xlps0,ylps0,xlib0,ylib0,xdis0,ydis0] = getMsg(file)
    pointList.append([xlps0,ylps0])

plt.rc('font',family='Times New Roman')

drawFig(pointList,elfNames,"./fig.png")

for elfFile in elfFiles:
    elfFile.close()