import asyncio
import time
import io

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

import PIL.Image
import PIL.ImageDraw
import PIL.ImageFont
import PIL.ImageChops

import matplotlib.pyplot as plt

# CRC8 table extracted from APK, pretty standard though
crc8_table = [
    0x00, 0x07, 0x0e, 0x09, 0x1c, 0x1b, 0x12, 0x15, 0x38, 0x3f, 0x36, 0x31,
    0x24, 0x23, 0x2a, 0x2d, 0x70, 0x77, 0x7e, 0x79, 0x6c, 0x6b, 0x62, 0x65,
    0x48, 0x4f, 0x46, 0x41, 0x54, 0x53, 0x5a, 0x5d, 0xe0, 0xe7, 0xee, 0xe9,
    0xfc, 0xfb, 0xf2, 0xf5, 0xd8, 0xdf, 0xd6, 0xd1, 0xc4, 0xc3, 0xca, 0xcd,
    0x90, 0x97, 0x9e, 0x99, 0x8c, 0x8b, 0x82, 0x85, 0xa8, 0xaf, 0xa6, 0xa1,
    0xb4, 0xb3, 0xba, 0xbd, 0xc7, 0xc0, 0xc9, 0xce, 0xdb, 0xdc, 0xd5, 0xd2,
    0xff, 0xf8, 0xf1, 0xf6, 0xe3, 0xe4, 0xed, 0xea, 0xb7, 0xb0, 0xb9, 0xbe,
    0xab, 0xac, 0xa5, 0xa2, 0x8f, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9d, 0x9a,
    0x27, 0x20, 0x29, 0x2e, 0x3b, 0x3c, 0x35, 0x32, 0x1f, 0x18, 0x11, 0x16,
    0x03, 0x04, 0x0d, 0x0a, 0x57, 0x50, 0x59, 0x5e, 0x4b, 0x4c, 0x45, 0x42,
    0x6f, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7d, 0x7a, 0x89, 0x8e, 0x87, 0x80,
    0x95, 0x92, 0x9b, 0x9c, 0xb1, 0xb6, 0xbf, 0xb8, 0xad, 0xaa, 0xa3, 0xa4,
    0xf9, 0xfe, 0xf7, 0xf0, 0xe5, 0xe2, 0xeb, 0xec, 0xc1, 0xc6, 0xcf, 0xc8,
    0xdd, 0xda, 0xd3, 0xd4, 0x69, 0x6e, 0x67, 0x60, 0x75, 0x72, 0x7b, 0x7c,
    0x51, 0x56, 0x5f, 0x58, 0x4d, 0x4a, 0x43, 0x44, 0x19, 0x1e, 0x17, 0x10,
    0x05, 0x02, 0x0b, 0x0c, 0x21, 0x26, 0x2f, 0x28, 0x3d, 0x3a, 0x33, 0x34,
    0x4e, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5c, 0x5b, 0x76, 0x71, 0x78, 0x7f,
    0x6a, 0x6d, 0x64, 0x63, 0x3e, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2c, 0x2b,
    0x06, 0x01, 0x08, 0x0f, 0x1a, 0x1d, 0x14, 0x13, 0xae, 0xa9, 0xa0, 0xa7,
    0xb2, 0xb5, 0xbc, 0xbb, 0x96, 0x91, 0x98, 0x9f, 0x8a, 0x8d, 0x84, 0x83,
    0xde, 0xd9, 0xd0, 0xd7, 0xc2, 0xc5, 0xcc, 0xcb, 0xe6, 0xe1, 0xe8, 0xef,
    0xfa, 0xfd, 0xf4, 0xf3
]

def crc8(data):
    crc = 0
    for byte in data:
        crc = crc8_table[(crc ^ byte) & 0xFF]
    return crc & 0xFF

_taskQueue = []
_address = ""

# General message format:  
# Magic number: 2 bytes 0x51, 0x78
# Command: 1 byte
# 0x00
# Data length: 1 byte
# 0x00
# Data: Data Length bytes
# CRC8 of Data: 1 byte
# 0xFF
def formatMessage(command, data):
    data = [ 0x51, 0x78 ] + [command] + [0x00] + [len(data)] + [0x00] + data + [crc8(data)] + [0xFF]
    return data

# Commands
RetractPaper = 0xA0     # Data: Number of steps to go back
FeedPaper = 0xA1        # Data: Number of steps to go forward
DrawBitmap = 0xA2       # Data: Line to draw. 0 bit -> don't draw pixel, 1 bit -> draw pixel
DrawingMode = 0xBE      # Data: 1 for Text, 0 for Images
SetEnergy = 0xAF        # Data: 1 - 0xFFFF
SetQuality = 0xA4       # Data: 1 - 5

PrinterCharacteristic = "0000AE01-0000-1000-8000-00805F9B34FB"

def _drawMath(math):
    buf = io.BytesIO()
    plt.rc('text', usetex=True)
    plt.rc('font', family='serif')
    plt.axis('off')
    plt.text(0.05, 0.5, f"${math}$", size=38)
    plt.savefig(buf, format='png')
    plt.close()

    im = PIL.Image.open(buf)
    im = im.resize((int(im.width / 2), int(im.height / 2)))
    bg = PIL.Image.new(im.mode, im.size, im.getpixel((0,0)))
    diff = PIL.ImageChops.difference(im, bg)
    diff = PIL.ImageChops.add(diff, diff, 2.0, -100)
    bbox = diff.getbbox()
    region = im.crop(bbox)
    im.paste(region, (0, 0, region.width, region.height))
    return im

def _drawText(text, font):
    img = PIL.Image.new('RGBA', (0,0), (255, 255, 255, 0))
    draw = PIL.ImageDraw.Draw(img)
    text_size = draw.textsize(text, font)

    img = PIL.Image.new('RGBA', text_size, (255, 255, 255, 0))
    draw = PIL.ImageDraw.Draw(img)
    draw.text((0,0), text, (0,0,0), font)
    return img

async def _drawSeperator(client):
    for i in range(0, 3):
        await client.write_gatt_char(PrinterCharacteristic, formatMessage(DrawBitmap, [0xFF] * 50))
        await client.write_gatt_char(PrinterCharacteristic, formatMessage(FeedPaper, [0, 1]))

async def _printImage(image, client):
    lineEmpty = True
    for y in range(0, image.height): 
        bmp = []
        bit = 0

        # Turn RGBA8 line into 1bpp
        for x in range(0, image.width):
            if bit % 8 == 0:
                bmp += [0x00]
            r, g, b, a = image.getpixel((x, y))
            bmp[int(bit / 8)] >>= 1
            if r < 0x80 and g < 0x80 and b < 0x80 and a > 0x80:
                bmp[int(bit / 8)] |= 0x80
                lineEmpty = False
            else:
                bmp[int(bit / 8)] |= 0

            bit += 1

        if lineEmpty:
            continue

        # Draw line
        await client.write_gatt_char(PrinterCharacteristic, formatMessage(DrawBitmap, bmp))
        # Advance line one step
        await client.write_gatt_char(PrinterCharacteristic, formatMessage(FeedPaper, [0, 1]))
        # Wait a bit to prevent printer from getting jammed. This can be fixed by sending compressed data like the app does. However I did not yet RE this.
        time.sleep(0.04)

    await client.write_gatt_char(PrinterCharacteristic, formatMessage(FeedPaper, [0x5, 0x00]))

async def _print():
    global _taskQueue

    if _address == "":
        raise RuntimeError("No Printer address set.")

    device = await BleakScanner.find_device_by_address(_address, timeout=20.0)
    if not device:
        raise BleakError(f"No device with address {_address} could not be found.")
    async with BleakClient(device) as client:
        # Set energy used to a moderate level
        await client.write_gatt_char(PrinterCharacteristic, formatMessage(SetEnergy, [0x10, 0x00])) 
        # Set print quality to high
        await client.write_gatt_char(PrinterCharacteristic, formatMessage(SetQuality, [5]))
        # Set mode to image mode
        await client.write_gatt_char(PrinterCharacteristic, formatMessage(DrawingMode, [0]))

        for task in _taskQueue:
            await task(client)
            time.sleep(0.1)
        
        clearQueue()

def setEnergyLevel(level):
    global _taskQueue
    _taskQueue += [ lambda client : client.write_gatt_char(PrinterCharacteristic, formatMessage(SetEnergy, [(level >> 8) & 0xFF, level & 0xFF])) ]

def setPrintQuality(quality):
    global _taskQueue
    _taskQueue += [ lambda client : client.write_gatt_char(PrinterCharacteristic, formatMessage(SetQuality, [quality])) ]

def setDrawingMode(mode):
    global _taskQueue
    _taskQueue += [ lambda client : client.write_gatt_char(PrinterCharacteristic, formatMessage(DrawingMode, [mode])) ]

def feedPaper(length):
    global _taskQueue
    _taskQueue += [ lambda client : client.write_gatt_char(PrinterCharacteristic, formatMessage(FeedPaper, [(length >> 8) & 0xFF, length & 0xFF])) ]

def retractPaper(length):
    global _taskQueue
    _taskQueue += [ lambda client : client.write_gatt_char(PrinterCharacteristic, formatMessage(RetractPaper, [(length >> 8) & 0xFF, length & 0xFF])) ]

def addImage(image):
    global _taskQueue
    _taskQueue += [ lambda client : _printImage(image, client) ]

def addText(text, font):
    global _taskQueue
    _taskQueue += [ lambda client : _printImage(_drawText(text, font), client) ]

def addMath(math):
    global _taskQueue
    _taskQueue += [ lambda client : _printImage(_drawMath(math), client) ]

def addSeperator():
    global _taskQueue
    _taskQueue += [ lambda client : _drawSeperator(client) ]
    
def clearQueue():
    global _taskQueue
    _taskQueue = []

def printOut():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_print())