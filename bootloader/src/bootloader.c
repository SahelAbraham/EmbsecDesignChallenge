// Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-13.

/*
################  ORIGINAL INSECURE BOOTLOADER CODE - DO NOT USE  ######################
*/

// Includes
#include <stdbool.h>
// Hardware Imports
#include "inc/hw_memmap.h" // Peripheral Base Addresses
#include "inc/lm3s6965.h"  // Peripheral Bit Masks and Registers
#include "inc/hw_types.h"  // Boolean type
#include "inc/hw_ints.h"   // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/sysctl.h"    // System control API (clock/reset)
#include "driverlib/interrupt.h" // Interrupt API

// Beaver SSL
#include <beaverssl.h>

// Library Imports
#include <string.h>
#include <beaverssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

// Application Imports
#include "uart.h"

// Forward Declarations
void load_initial_firmware(void);
void load_firmware(void);
void boot_firmware(void);
long program_flash(uint32_t, unsigned char *, unsigned int);
bool verify_frame(unsigned char *frame_data, int frame_len, unsigned char *hashed_checksum);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4
#define MAX_FW 20000

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Firmware v2 is embedded in bootloader
// Read up on these symbols in the objcopy man page (if you want)!
extern int _binary_firmware_bin_start;
extern int _binary_firmware_bin_size;

// Device metadata
uint16_t *fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t *fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t *fw_release_message_address;
void uart_write_hex_bytes(uint8_t uart, uint8_t *start, uint32_t len);

// Firmware Buffer

int main(void)
{

    // A 'reset' on UART0 will re-start this code at the top of main, won't clear flash, but will clean ram.

    // Initialize UART channels
    // 0: Reset
    // 1: Host Connection
    // 2: Debug
    uart_init(UART0);
    uart_init(UART1);
    uart_init(UART2);

    // Enable UART0 interrupt
    IntEnable(INT_UART0);
    IntMasterEnable();

    load_initial_firmware(); // note the short-circuit behavior in this function, it doesn't finish running on reset!

    uart_write_str(UART2, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART2, "Send \"U\" to update, and \"B\" to run the firmware.\n");
    uart_write_str(UART2, "Writing 0x20 to UART0 will reset the device.\n");

    int resp;
    while (1)
    {
        uint32_t instruction = uart_read(UART1, BLOCKING, &resp);
        if (instruction == UPDATE)
        {
            uart_write_str(UART1, "U");
            load_firmware();
            uart_write_str(UART2, "Loaded new firmware.\n");
            nl(UART2);
        }
        else if (instruction == BOOT)
        {
            uart_write_str(UART1, "B");
            boot_firmware();
        }
    }
}

/*
 * Load initial firmware into flash
 */
void load_initial_firmware(void)
{

    if (*((uint32_t *)(METADATA_BASE)) != 0xFFFFFFFF)
    {
        /*
         * Default Flash startup state is all FF since. Only load initial
         * firmware when metadata page is all FF. Thus, exit if there has
         * been a reset!
         */
        return;
    }

    // Create buffers for saving the release message
    uint8_t temp_buf[FLASH_PAGESIZE];
    char initial_msg[] = "This is the initial release message.";
    uint16_t msg_len = strlen(initial_msg) + 1;
    uint16_t rem_msg_bytes;

    // Get included initial firmware
    int size = (int)&_binary_firmware_bin_size;
    uint8_t *initial_data = (uint8_t *)&_binary_firmware_bin_start;

    // Set version 2 and install
    uint16_t version = 2;
    uint32_t metadata = (((uint16_t)size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

    int i;

    for (i = 0; i < size / FLASH_PAGESIZE; i++)
    {
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), initial_data + (i * FLASH_PAGESIZE), FLASH_PAGESIZE);
    }

    /* At end of firmware. Since the last page may be incomplete, we copy the initial
     * release message into the unused space in the last page. If the firmware fully
     * uses the last page, the release message simply is written to a new page.
     */

    uint16_t rem_fw_bytes = size % FLASH_PAGESIZE;
    if (rem_fw_bytes == 0)
    {
        // No firmware left. Just write the release message
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)initial_msg, msg_len);
    }
    else
    {
        // Some firmware left. Determine how many bytes of release message can fit
        if (msg_len > (FLASH_PAGESIZE - rem_fw_bytes))
        {
            rem_msg_bytes = msg_len - (FLASH_PAGESIZE - rem_fw_bytes);
        }
        else
        {
            rem_msg_bytes = 0;
        }

        // Copy rest of firmware
        memcpy(temp_buf, initial_data + (i * FLASH_PAGESIZE), rem_fw_bytes);
        // Copy what will fit of the release message
        memcpy(temp_buf + rem_fw_bytes, initial_msg, msg_len - rem_msg_bytes);
        // Program the final firmware and first part of the release message
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), temp_buf, rem_fw_bytes + (msg_len - rem_msg_bytes));

        // If there are more bytes, program them directly from the release message string
        if (rem_msg_bytes > 0)
        {
            // Writing to a new page. Increment pointer
            i++;
            program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)(initial_msg + (msg_len - rem_msg_bytes)), rem_msg_bytes);
        }
    }
}

/*
 * Load the firmware into flash.
 */
void load_firmware(void)
{
    int frame_length = 0;
    int read = 0;
    uint32_t rcv = 0;

    uint32_t data_index = 0;
    uint32_t page_addr = FW_BASE;
    uint32_t version = 0;
    uint32_t size = 0;

    // Get size as 2 bytes
    rcv = uart_read(UART1, BLOCKING, &read);
    size = (uint32_t)rcv;
    rcv = uart_read(UART1, BLOCKING, &read);
    size |= (uint32_t)rcv << 8;

    unsigned char data[size];

    uart_write_str(UART0, "Received Firmware Size: ");
    uart_write_hex(UART0, size);
    nl(UART0);

    unsigned char gcm_nonce[12];
    unsigned char tag[16];

    for (int i = 0; i < 12; i++)
    {
        gcm_nonce[i] = uart_read(UART1, BLOCKING, &read);
    }
    for (int i = 0; i < 16; i++)
    {
        tag[i] = uart_read(UART1, BLOCKING, &read);
    }

    uart_write_str(UART0, "Received nonce+tag");
    nl(UART0);

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

    uart_write(UART1, OK); // Acknowledge the metadata.

    /* Loop here until you can get all your characters and stuff */
    while (1)
    {
        // Get start frame endian short
        rcv = uart_read(UART1, BLOCKING, &read);
        int start_short = (int)rcv;
        rcv = uart_read(UART1, BLOCKING, &read);
        start_short |= (int)rcv << 8;

        if (start_short != 1)
        {
            uart_write(UART1, ERROR); // Reject the metadata.
            SysCtlReset();            // Reset device
            return;
        }

        // Get two bytes for the length.
        rcv = uart_read(UART1, BLOCKING, &read);
        frame_length = (int)rcv << 8;
        rcv = uart_read(UART1, BLOCKING, &read);
        frame_length += (int)rcv;
        if (frame_length == 0)
        {
            uart_write(UART1, OK); // Acknowledge the frame.
            break;
        }
        unsigned char tempdata[frame_length];
        // Get the 256 length data
        for (int i = 0; i < frame_length; i++)
        {
            data[data_index] = uart_read(UART1, BLOCKING, &read);
            tempdata[i] = data[data_index];
            if (data_index >= sizeof(data))
            {
                uart_write(UART1, ERROR); // Reject the metadata.
                SysCtlReset();            // Reset device
                return;
            }
            data_index += 1;
        }
        unsigned char checksums[32];
        // Get the 32 length checksum
        for (int i = 0; i < 32; i++)
        {
            checksums[i] = uart_read(UART1, BLOCKING, &read);
        }

        bool verified = verify_frame(tempdata, 256, checksums);
        if (verified)
        {
            uart_write(UART1, OK); // Acknowledge the frame.
        }
        else
        {
            uart_write(UART1, ERROR); // Reject the metadata.
            SysCtlReset();            // Reset device
            return;
        }
    }
    //aes_decrypt(data,gcm_nonce,tag);
    // decrypt and load raw data into flash
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(uint32_t page_addr, unsigned char *data, unsigned int data_len)
{
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase(page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE)
    {
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, page_addr, num_full_bytes);
        if (ret != 0)
        {
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++)
        {
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++)
        {
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, page_addr + num_full_bytes, 4);
    }
    else
    {
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, page_addr, data_len);
    }
}

void boot_firmware(void)
{
    // compute the release message address, and then print it
    uint16_t fw_size = *fw_size_address;
    fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
    uart_write_str(UART2, (char *)fw_release_message_address);

    // Boot the firmware
    __asm(
        "LDR R0,=0x10001\n\t"
        "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t *start, uint32_t len)
{
    for (uint8_t *cursor = start; cursor < (start + len); cursor += 1)
    {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9)
        {
            right_nibble += 0x37;
        }
        else
        {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9)
        {
            left_nibble += 0x37;
        }
        else
        {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';

        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}
//bytes to hex (?)
void byteToHexString(unsigned char byte, char* hexString) {
    static const char hexChars[] = "0123456789ABCDEF";
    hexString[0] = hexChars[(byte >> 4) & 0xF];
    hexString[1] = hexChars[byte & 0xF];
    hexString[2] = '\0'; // Null-terminate the string
}


// verifying if checksum for frames are correct
bool verify_frame(unsigned char *frame_data, int frame_len, unsigned char *hashed_checksum)
{
    unsigned int new_checksum = 0; 

    // Calculate checksum each custom algorithm
    for (uint32_t i = 0; i < frame_len; i++)
    {
        new_checksum += frame_data[i];
    }
    
    int numlength = 0;
    int tempnum = new_checksum;
    while(tempnum>0){
        tempnum = tempnum/10;
        numlength++;
    }
    tempnum = new_checksum;
    char checksumarray[numlength];
    while(tempnum>0){
        numlength--;
        checksumarray[numlength] = (char)tempnum%10;
        tempnum = tempnum/10;
    }

    unsigned char hash[32];
    sha_hash("a", 1, hash);

    // check hashes
    // for (int i = 0; i < 64; i++)
    // {
    //     if (hash[i] != hashed_checksum[i])
    //     {
    //         return false;
    //     }
    //     if (sizeof(hash[i]) != sizeof(hashed_checksum[i]))
    //     {
    //         return false;
    //     }
    // }
    // hash_sum = 0
    // for(int i = 0; i<32; i++){
    //      hash_sum += hash[i]<<16*i
    //     }
    // hash_sum = 0
    // for(int i = 0; i<32; i++){
    //      hash_sum += hash[i]<<16*i
    //     }
    // if((hash^hashed_checksum)!=0){
    //     return false;
    // }
    return true;
}