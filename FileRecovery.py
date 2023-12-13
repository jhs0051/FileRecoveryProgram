# Digital Forensics
# Project 2
# By: Jonathan Seibert and Andrew Painton
# Date: 11/03/2023

# Project Description:
# take a disk image Download disk images an input, locate file signatures,
# properly recover user generated files without corruption, and generates an SHA-256 hash for each file recovered.

# Supported file types:
# MPG
# PDF
# BMP
# GIF
# JPG
# DOCX
# AVI
# PNG
# ZIP (For extra credit)

import sys
import os
import math

# Global variables

# list of file types and their signatures hex values to locate the files
fileSignatureHexValues = {'MPG': '000001b3',
                          'PDF': '25504446',
                          'BMP': '424d',
                          'GIF': '474946383961',
                          'JPG': 'ffd8ff',
                          'DOCX': '504b030414000600',
                          'AVI': '52494646',
                          'PNG': '89504e470d0a1a0a',
                          'ZIP': '504b0304'}

# list of file types and their trailers hex values to locate the end of the files
endOfFileHexValues = {'MPGType1': '000001b7',
                      'MPGType2': '000001b9',
                      'PDFType1': '0d2525454f460d000000',
                      'PDFType2': '0d0a2525454f460d0a000000',
                      'PDFType3': '0a2525454f460a000000',
                      'PDFType4': '0a2525454f46000000',
                      'GIF': '003b000000',
                      'JPG': 'ffd9000000',
                      'DOCX': '504b0506',
                      'PNG': '49454e44ae426082',
                      'ZIP': '504b0506'}

# Keeps track of recovered files to iterate through the naming convention when recovering them
currentRecoveredFileCount = 0


# This function allows script to open a disk image and turn the values into a list of hex values
def openTargetImage(userDiskImage):
    print('========================================')
    print('Trying to open disk image provided')
    print('========================================')

    # try and open the disk image and convert them to a hex value to use later
    try:
        with open(userDiskImage, 'rb') as diskImage:
            diskHexValues = diskImage.read().hex()
        print('analyzing contents of disk image')
    except FileNotFoundError:
        print(f'Error: File not found - {userDiskImage}')
        return None
    else:
        print('========================================')
        print('Contents collected. Closing disk image to begin file recovery')
        print('========================================')
        return diskHexValues


# This function is used to locate the number of files in the disk image
def locateFiles(diskContents):
    print('========================================')
    print('Searching for files. For larger files like audio files, this may take a moment. Please wait.\n')
    print('========================================')

    for hexValue in fileSignatureHexValues:
        findAndRecoverFiles(diskContents, hexValue)

    # Prints out total number of files found after searching through the entire disk image
    print('========================================')
    print('The contents of the disk have been examined\n')
    print(f'I recovered the files. They will be located in the project directory')
    print(
        'If you would like to run the process again on another disk, simply run the program again with a new disk image'
    )
    print('========================================')


# Searches disk contents for matching hex values and calls the specific function type to recover the file on a match
def findAndRecoverFiles(diskContents, hexValue):
    print('========================================')
    print(f'Finding and recovering {hexValue} files')
    print('========================================')

    hexIdentifier = diskContents.find(fileSignatureHexValues[hexValue])

    recovery_functions = {
        'MPG': recoverMPGFiles,
        'PDF': recoverPDFFiles,
        'BMP': recoverBMPFiles,
        'GIF': recoverGIFFiles,
        'JPG': recoverJPGFiles,
        'DOCX': recoverDOCXFiles,
        'AVI': recoverAVIFiles,
        'PNG': recoverPNGFiles,
        'ZIP': recoverZIPFiles
    }

    while hexIdentifier != -1 and hexValue in recovery_functions:
        recovery_functions[hexValue](diskContents, hexIdentifier)
        hexIdentifier = diskContents.find(fileSignatureHexValues.get(hexValue), hexIdentifier + 1)


# Common function to print the file offset information for each file name
def printFileInfo(fileName, startingOffsetBytes, endingOffsetBytes):
    print(f'{fileName}, ', end='')
    print(f'Start Offset: {hex(startingOffsetBytes)}, ', end='')
    print(f'End Offset: {hex(endingOffsetBytes)}')


# Common function to hash the recovered files using SHA-256 hash
def hashFile(args, fileName, startingOffsetBytes, fileSize):
    # command to recover the files to the system
    recoverFiles = f'dd if={sys.argv[1]} of={fileName} bs=1 skip={startingOffsetBytes} count={fileSize}'
    os.system(recoverFiles)

    # Generate the hash for the recovered file
    generateHash = f'sha256sum {fileName}'
    print(f'SHA-256: ', end='')
    sys.stdout.flush()
    os.system(generateHash)


# Function to recover MPG files
def recoverMPGFiles(diskContents, hexIdentifier):
    # Check for files starting at the beginning of a sector
    if (hexIdentifier % 512) == 0:
        global currentRecoveredFileCount
        currentRecoveredFileCount += 1

        # Check for one of the hex trailers for the MPG Files
        mpgFileType1 = endOfFileHexValues['MPGType1']
        mpgFileType2 = endOfFileHexValues['MPGType2']

        # Search for the first end of the trailer type
        fileEndBytes = diskContents.find(mpgFileType1, hexIdentifier)
        if fileEndBytes != 8:

            # If the first trailers is not found, try the second trailer type
            if fileEndBytes == -1:
                fileEndBytes = diskContents.find(mpgFileType2, hexIdentifier)

            # Add 7 bytes so that we are at the index of the last byte in the file's trailer
            fileEndBytes += 7

            # Calculate file info and print it
            fileName = f'File{currentRecoveredFileCount}.mpg'

            # Calculate the file's offset in bytes
            startingOffsetBytes = int(hexIdentifier / 2)
            endingOffsetBytes = int(math.ceil(fileEndBytes / 2))
            fileSize = endingOffsetBytes - startingOffsetBytes

            # Print file information: file name, start offset, and end offset
            printFileInfo(fileName, startingOffsetBytes, endingOffsetBytes)

            # Recover file using the file info we calculated and get SHA-256 hash
            hashFile(sys.argv[1], fileName, startingOffsetBytes, fileSize)


# Function to recover PDF files
def recoverPDFFiles(diskContents, hexIdentifier):
    # Check for files starting at the beginning of a sector
    if (hexIdentifier % 512) == 0:
        global currentRecoveredFileCount
        currentRecoveredFileCount += 1

        # Check for one of the hex trailers for the PDF Files
        PDFTypes = ['PDFType1', 'PDFType2', 'PDFType3', 'PDFType4']

        fileEndBytes = -1 # Default when pdf is not found so that we can search for other types
        endingOffsetBytes = 13  # length of trailer for pdf for two types of pdf files

        for fileType in PDFTypes:
            fileEndBytes = diskContents.find(endOfFileHexValues[fileType], hexIdentifier)
            if fileEndBytes != -1:
                if fileType == 'PDFType2':
                    endingOffsetBytes = 17 # length of trailer
                elif fileType == 'PDFType4':
                    endingOffsetBytes = 11 # length of trailer
                break

        # calculate file offset
        if fileEndBytes != -1:
            endingOffsetBytes += fileEndBytes

        # Calculate file info and print it
        fileName = f'File{currentRecoveredFileCount}.pdf'

        # Calculate the file's offset in bytes, must divide by 2 for correct offset because 1 byte = 2 hex characters
        startingOffsetBytes = int(hexIdentifier / 2)
        endingOffsetBytes = int(math.ceil(endingOffsetBytes / 2))
        fileSize = endingOffsetBytes - startingOffsetBytes

        # Print file information: file name, start offset, and end offset
        printFileInfo(fileName, startingOffsetBytes, endingOffsetBytes)

        # Recover file using the file info we calculated and get SHA-256 hash
        hashFile(sys.argv[1], fileName, startingOffsetBytes, fileSize)


# Function to recover BMP files
def recoverBMPFiles(diskContents, hexIdentifier):
    # Check for files starting at the beginning of a sector and the reserved bits are 0
    if (hexIdentifier % 512) == 0 and (diskContents[(hexIdentifier + 12):(hexIdentifier + 20)] == '00000000'):
        global currentRecoveredFileCount
        currentRecoveredFileCount += 1

        # Calculate file info and print it
        fileName = f'File{currentRecoveredFileCount}.bmp'

        # Get the file size which is the next four bytes after the signature (little endian order)
        byte1 = diskContents[hexIdentifier + 4:hexIdentifier + 6]
        byte2 = diskContents[hexIdentifier + 6:hexIdentifier + 8]
        byte3 = diskContents[hexIdentifier + 8:hexIdentifier + 10]
        byte4 = diskContents[hexIdentifier + 10:hexIdentifier + 12]

        # Concatenate the bytes to form a hexadecimal string
        hexSize = byte4 + byte3 + byte2 + byte1

        # Convert the hexadecimal string to an integer
        fileSize = int(hexSize, 16)

        # Calculate the file's offset in bytes, must divide by 2 for correct offset because 1 byte = 2 hex characters
        startingOffsetBytes = int(hexIdentifier / 2)
        endingOffsetBytes = startingOffsetBytes + fileSize

        # Print file information: file name, start offset, and end offset
        printFileInfo(fileName, startingOffsetBytes, endingOffsetBytes)

        # Recover file using the file info we calculated and get SHA-256 hash
        hashFile(sys.argv[1], fileName, startingOffsetBytes, fileSize)


# Function to recover GIF files
def recoverGIFFiles(diskContents, hexIdentifier):
    # Check for files starting at the beginning of a sector
    if (hexIdentifier % 512) == 0:
        global currentRecoveredFileCount
        currentRecoveredFileCount += 1

        # Search for the first end of the trailer type
        fileEndBytes = diskContents.find(endOfFileHexValues['GIF'], hexIdentifier)

        # Add 3 bytes so that we are at the index of the last byte in the file's trailer
        fileEndBytes = fileEndBytes + 3

        # Calculate file info and print it
        fileName = f'File{currentRecoveredFileCount}.gif'

        # Calculate the file's offset in bytes, must divide by 2 for correct offset because 1 byte = 2 hex characters
        startingOffsetBytes = int(hexIdentifier / 2)
        endingOffsetBytes = int(math.ceil(fileEndBytes / 2))
        fileSize = endingOffsetBytes - startingOffsetBytes

        # Print file information: file name, start offset, and end offset
        printFileInfo(fileName, startingOffsetBytes, endingOffsetBytes)

        # Recover file using the file info we calculated and get SHA-256 hash
        hashFile(sys.argv[1], fileName, startingOffsetBytes, fileSize)


# Function to recover JPG files
def recoverJPGFiles(diskContents, hexIdentifier):
    # Check for files starting at the beginning of a sector
    if (hexIdentifier % 512) == 0:
        global currentRecoveredFileCount
        currentRecoveredFileCount += 1

        # Search for the first end of the trailer type
        fileEndBytes = diskContents.find(endOfFileHexValues['JPG'], hexIdentifier)

        # Add 3 bytes so that we are at the index of the last byte in the file's trailer
        fileEndBytes = fileEndBytes + 3

        # Calculate file info and print it
        fileName = f'File{currentRecoveredFileCount}.jpg'

        # Calculate the file's offset in bytes, must divide by 2 for correct offset because 1 byte = 2 hex characters
        startingOffsetBytes = int(hexIdentifier / 2)
        endingOffsetBytes = int(math.ceil(fileEndBytes / 2))
        fileSize = endingOffsetBytes - startingOffsetBytes

        # Print file information: file name, start offset, and end offset
        printFileInfo(fileName, startingOffsetBytes, endingOffsetBytes)

        # Recover file using the file info we calculated and get SHA-256 hash
        hashFile(sys.argv[1], fileName, startingOffsetBytes, fileSize)


# Function to recover DOCX files
def recoverDOCXFiles(diskContents, hexIdentifier):
    # Check for files starting at the beginning of a sector
    if (hexIdentifier % 512) == 0:
        global currentRecoveredFileCount
        currentRecoveredFileCount += 1

        # Search for the first end of the trailer type
        fileEndBytes = diskContents.find(endOfFileHexValues['DOCX'], hexIdentifier)

        # Add 43 bytes so that we are at the index of the last byte in the file's trailer
        fileEndBytes = fileEndBytes + 43

        # Calculate file info and print it
        fileName = f'File{currentRecoveredFileCount}.docx'

        # Calculate the file's offset in bytes, must divide by 2 for correct offset because 1 byte = 2 hex characters
        startingOffsetBytes = int(hexIdentifier / 2)
        endingOffsetBytes = int(math.ceil(fileEndBytes / 2))
        fileSize = endingOffsetBytes - startingOffsetBytes

        # Print file information: file name, start offset, and end offset
        printFileInfo(fileName, startingOffsetBytes, endingOffsetBytes)

        # Recover file using the file info we calculated and get SHA-256 hash
        hashFile(sys.argv[1], fileName, startingOffsetBytes, fileSize)


# Function to recover AVI files
def recoverAVIFiles(diskContents, hexIdentifier):
    # Check that the signature is at the beginning of a sector and the last part of the head is present
    if (hexIdentifier % 512) == 0 and (diskContents[(hexIdentifier + 16):(hexIdentifier + 32)] == '415649204c495354'):
        global currentRecoveredFileCount
        currentRecoveredFileCount += 1

        # Calculate file info and print it
        fileName = f'File{currentRecoveredFileCount}.avi'

        # Get the file size which is the next four bytes after the signature (little endian order)
        # Extract bytes for the file size from diskContents
        byte1 = diskContents[hexIdentifier + 8:hexIdentifier + 10]
        byte2 = diskContents[hexIdentifier + 10:hexIdentifier + 12]
        byte3 = diskContents[hexIdentifier + 12:hexIdentifier + 14]
        byte4 = diskContents[hexIdentifier + 14:hexIdentifier + 16]

        # Concatenate the bytes to form a hexadecimal string
        hexSize = byte4 + byte3 + byte2 + byte1

        # Convert the hexadecimal string to an integer and add 8
        fileSize = int(hexSize, 16) + 8

        # Calculate the file's offset in bytes, must divide by 2 for correct offset because 1 byte = 2 hex characters
        startingOffsetBytes = int(hexIdentifier / 2)
        endingOffsetBytes = startingOffsetBytes + fileSize

        # Print file information: file name, start offset, and end offset
        printFileInfo(fileName, startingOffsetBytes, endingOffsetBytes)

        # Recover file using the file info we calculated and get SHA-256 hash
        hashFile(sys.argv[1], fileName, startingOffsetBytes, fileSize)


# Function to recover PNG files
def recoverPNGFiles(diskContents, hexIdentifier):
    # Check for files starting at the beginning of a sector
    if (hexIdentifier % 512) == 0:
        global currentRecoveredFileCount
        currentRecoveredFileCount += 1

        # Search for the first end of the trailer type
        fileEndBytes = diskContents.find(endOfFileHexValues['PNG'], hexIdentifier)

        # Add 15 bytes so that we are at the index of the last byte in the file's trailer
        fileEndBytes = fileEndBytes + 15

        # Calculate file info and print it
        fileName = f'File{currentRecoveredFileCount}.png'

        # Calculate the file's offset in bytes, must divide by 2 for correct offset because 1 byte = 2 hex characters
        startingOffsetBytes = int(hexIdentifier / 2)
        endingOffsetBytes = int(math.ceil(fileEndBytes / 2))
        fileSize = endingOffsetBytes - startingOffsetBytes

        # Print file information: file name, start offset, and end offset
        printFileInfo(fileName, startingOffsetBytes, endingOffsetBytes)

        # Recover file using the file info we calculated and get SHA-256 hash
        hashFile(sys.argv[1], fileName, startingOffsetBytes, fileSize)


def recoverZIPFiles(diskContents, hexIdentifier):
    # Check for files starting at the beginning of a sector
    if (hexIdentifier % 512) == 0:
        global currentRecoveredFileCount
        currentRecoveredFileCount += 1

        # Search for the EOCD signature
        fileEndBytes = diskContents.find(endOfFileHexValues['ZIP'], hexIdentifier)

        # Read the comment length (2 bytes, little-endian) from 20 bytes after the signature
        comment_length_hex = diskContents[fileEndBytes + 42:fileEndBytes + 44] + diskContents[
                                                                                 fileEndBytes + 40:fileEndBytes + 42]
        comment_length = int(comment_length_hex, 16)

        # Adjust the fileEndBytes to account for the comment
        fileEndBytes += 22 + (
                    2 * comment_length)  # 22 bytes for EOCD without comment, and each byte in the comment is represented by 2 hex characters

        # Calculate file info and print it
        fileName = f'File{currentRecoveredFileCount}.zip'

        # Calculate the file's offset in bytes
        startingOffsetBytes = int(hexIdentifier / 2)
        endingOffsetBytes = int(math.ceil(fileEndBytes / 2))
        fileSize = endingOffsetBytes - startingOffsetBytes

        # Print file information: file name, start offset, and end offset
        printFileInfo(fileName, startingOffsetBytes, endingOffsetBytes)

        # Recover the ZIP file using the file info we calculated and get SHA-256 hash
        hashFile(sys.argv[1], fileName, startingOffsetBytes, fileSize)


# runs the program
def main():
    print('========================================')
    print('Welcome to the Disk Image Recovery Tool!')
    print('========================================')


# Checks length of command run by user to ensure they passed a disk image correctly
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(
            "Please pass the name of a single disk image which should be of type dd 'python3 FileRecovery.py"
            "<exampleDiskName.dd>'")
    else:
        userDiskImage = sys.argv[1]
        diskContents = openTargetImage(userDiskImage)
        locateFiles(diskContents)
