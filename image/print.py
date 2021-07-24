import asyncio
import platform
import time
import os

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

import PIL.Image

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
GetDevState = 0xA3      # Data: 0
ControlLattice = 0xA6   # Data: Eleven bytes, all constants. One set used before printing, one after.
GetDevInfo = 0xA8       # Data: 0
OtherFeedPaper = 0xBD   # Data: one byte, set to a device-specific "Speed" value before printing and to 0x19 before feeding blank paper
DrawingMode = 0xBE      # Data: 1 for Text, 0 for Images
SetEnergy = 0xAF        # Data: 1 - 0xFFFF
SetQuality = 0xA4       # Data: 0x31 - 0x35. APK always sets 0x33 for GB01

PrintLattice = [ 0xAA, 0x55, 0x17, 0x38, 0x44, 0x5F, 0x5F, 0x5F, 0x44, 0x38, 0x2C ]
FinishLattice = [ 0xAA, 0x55, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17 ]
XOff = ( 0x51, 0x78, 0xAE, 0x01, 0x01, 0x00, 0x10, 0x70, 0xFF )
XOn = ( 0x51, 0x78, 0xAE, 0x01, 0x01, 0x00, 0x00, 0x00, 0xFF )

PrinterWidth = 384
ImgPrintSpeed = [ 0x23 ]
BlankSpeed = [ 0x19 ]
PacketLength = 30   # This is the first value I tried; it might be too low

PrinterAddress = ""
PrinterCharacteristic = "0000AE01-0000-1000-8000-00805F9B34FB"
NotifyCharacteristic = "0000AE02-0000-1000-8000-00805F9B34FB"
device = None

# global flag for flow control signaling, because I don't know the right way to do this
transmit = True


def detect_printer(detected, advertisement_data):
    global device
    # This isn't necessarily a great way to detect the printer.
    # It's the way the app does it, but the app has an actual UI where you can pick your device from a list.
    # Ideally this function would filter for known characteristics, but I don't know how hard that would be or what
    # kinds of problems it could cause. For now, I just want to get my printer working.
    if detected.name == 'GB01':
        device = detected


def notification_handler(sender, data):
    global transmit
    print("{0}: [ {1} ]".format(sender, " ".join("{:02X}".format(x) for x in data)))
    if tuple(data) == XOff:
        print("Pausing transmission.")
        transmit = False
        return
    if tuple(data) == XOn:
        print("Resuming transmission.")
        transmit = True
        return
    if data[2] == GetDevState:
        print("printer status byte: {:08b}".format(data[6]))
        # xxxxxxx1 no_paper ("No paper.")
        # xxxxxx10 paper_positions_open ("Warehouse.")
        # xxxxx100 too_hot ("Too hot, please let me take a break.")
        # xxxx1000 no_power_please_charge ("I have no electricity, please charge")
        # I don't know if multiple status bits can be on at once, but if they are, then iPrint won't detect them.
        # In any case, I think the low battery flag is the only one the GB01 uses.
        return


async def connect_and_send(data):
    scanner = BleakScanner()
    scanner.register_detection_callback(detect_printer)
    await scanner.start()
    for x in range(50):
        await asyncio.sleep(0.1)
        if device:
            break
    await scanner.stop()

    if not device:
        raise BleakError(f"No device named GB01 could be found.")
    async with BleakClient(device) as client:
        # Set up callback to handle messages from the printer
        await client.start_notify(NotifyCharacteristic, notification_handler)

        while(data):
            # Cut the command stream up into pieces small enough for the printer to handle
            await client.write_gatt_char(PrinterCharacteristic, data[:PacketLength])
            data = data[PacketLength:]
            await asyncio.sleep(0.01)
            while not transmit:
                # Pause transmission per printer request.
                # Note: doing it this way does not appear to actually work.
                await asyncio.sleep(0)


def drawTestPattern():
        cmdqueue = []
        # Ask the printer how it's doing
        cmdqueue += formatMessage(GetDevState, [0x00])
        # Set quality to standard
        cmdqueue += formatMessage(SetQuality, [0x33])
        # start and/or set up the lattice, whatever that is
        cmdqueue += formatMessage(ControlLattice, PrintLattice)
        # Set energy used to a moderate level
        cmdqueue += formatMessage(SetEnergy, [0xE0, 0x2E])
        # Set mode to image mode
        cmdqueue += formatMessage(DrawingMode, [0])
        # not entirely sure what this does
        cmdqueue += formatMessage(OtherFeedPaper, ImgPrintSpeed)

        image = PIL.Image.open(os.path.abspath(os.path.dirname(__file__)) + "/image.png")
        if image.width > PrinterWidth:
            # image is wider than printer resolution; scale it down proportionately
            height = int(image.height * (PrinterWidth / image.width))
            image = image.resize((PrinterWidth, height))
        # convert image to black-and-white 1bpp color format
        image = image.convert("1")
        if image.width < PrinterWidth:
            # image is narrower than printer resolution; pad it out with white pixels
            padded_image = PIL.Image.new("1", (PrinterWidth, image.height), 1)
            padded_image.paste(image)
            image = padded_image

        for y in range(0, image.height):
            bmp = []
            bit = 0
            # pack image data into 8 pixels per byte
            for x in range(0, image.width):
                if bit % 8 == 0:
                    bmp += [0x00]
                bmp[int(bit / 8)] >>= 1
                if not image.getpixel((x, y)):
                    bmp[int(bit / 8)] |= 0x80
                else:
                    bmp[int(bit / 8)] |= 0

                bit += 1

            cmdqueue += formatMessage(DrawBitmap, bmp)

        # Feed extra paper for image to be visible
        cmdqueue += formatMessage(OtherFeedPaper, BlankSpeed)
        cmdqueue += formatMessage(FeedPaper, [0x70, 0x00])

        # iPrint sends another GetDevState request at this point, but we're not staying long enough for an answer

        # finish the lattice, whatever that means
        cmdqueue += formatMessage(ControlLattice, FinishLattice)

        return cmdqueue


printdata = drawTestPattern()
loop = asyncio.get_event_loop()
loop.run_until_complete(connect_and_send(printdata))
