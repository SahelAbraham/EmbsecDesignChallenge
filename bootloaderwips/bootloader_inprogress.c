// Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-13.
/*
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⣤⣤⣤⣶⣦⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡿⠛⠉⠙⠛⠛⠛⠛⠻⢿⣿⣷⣤⡀⠀⠀⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⠋⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠈⢻⣿⣿⡄⠀⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⣸⣿⡏⠀⠀⠀⣠⣶⣾⣿⣿⣿⠿⠿⠿⢿⣿⣿⣿⣄⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⣿⣿⠁⠀⠀⢰⣿⣿⣯⠁⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣷⡄⠀ 
⠀⠀⣀⣤⣴⣶⣶⣿⡟⠀⠀⠀⢸⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣷⠀ 
⠀⢰⣿⡟⠋⠉⣹⣿⡇⠀⠀⠀⠘⣿⣿⣿⣿⣷⣦⣤⣤⣤⣶⣶⣶⣶⣿⠀ 
⠀⢸⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀ 
⠀⣸⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠉⠻⠿⣿⣿⣿⣿⡿⠿⠿⠛⢻⠀⠀ 
⠀⣿⣿⠁⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣧⠀⠀ 
⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀ 
⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀ 
⠀⢿⣿⡆⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀ 
⠀⠸⣿⣧⡀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠃⠀⠀ 
⠀⠀⠛⢿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⣰⣿⣿⣷⣶⣶⣶⣶⢠ ⣿⣿⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡇⠀⣽⣿⡏⠁⠀⠀⢸⣿⡇⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡇⠀⢹⣿⡆⠀⠀⠀ ⣸⣿⠇⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⢿⣿⣦⣄⣀⣠⣴⣿⣿⠁⠀⠈⠻⣿⣿⣿⣿⡿⠏⠀⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⠈⠛⠻⠿⠿⠿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
*/

//################  ALL CURRENT BOOTLOADER PROGRESS - MAY NOT WORK  ######################

//Includes 
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

// Library Imports
#include <string.h>
#include <beaverssl.h>
#include <stdio.h>
#include <stdlib.h>
// Application Imports
#include "uart.h"
#include "bootloader_secrets.h"

// Forward Declarations
void load_initial_firmware(void);
void load_firmware(void);
void boot_firmware(void);
long program_flash(uint32_t, unsigned char *, unsigned int);
void decrypt_aes(char*);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash
//Defines added
#define FRAME_START 0
#define FRAME_DATA 1
#define FRAME_END 2

#define FRAME_HEADER_SIZE 2
#define HASH_SIZE 32
// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')
#define START_FRAME ((unsigned char)0x00)
#define DATA_FRAME ((unsigned char)0x01)
#define END_FRAME ((unsigned char)0x02)
// Firmware v2 is embedded in bootloader
// Read up on these symbols in the objcopy man page (if you want)!
extern int _binary_firmware_bin_start;
extern int _binary_firmware_bin_size;

// Device metadata
uint16_t *fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t *fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t *fw_release_message_address;
void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len);

// Firmware Buffer
unsigned char* data;


FILE *fptr;

int main(void){

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
    while (1){
        uint32_t instruction = uart_read(UART1, BLOCKING, &resp);
        if (instruction == UPDATE){
            uart_write_str(UART1, "U");
            load_firmware();
            uart_write_str(UART2, "Loaded new firmware.\n");
            nl(UART2);
        }else if (instruction == BOOT){
            uart_write_str(UART1, "B");
            boot_firmware();
        }
    }
}
/*
//Compile back to cipher text 
char* compile_ciphertext(char** cipher_frames, int num_frames){
    int total_length = 0; 
    for(int i = 0; i < num_frames){
        total_length += strlen(cipher_frames[i]);
    }

    char* ciphertext = (char*)malloc(total_length+1);
    if(ciphertext == NULL){
        return NULL;
    }

    int offset = 0; 
    for(int i = 0; i < num_frames; i++){
        strcpy(ciphertext + offset. cipher_frames[i]);
        offset += strlen(cipher_frames[i]);
    }
    return ciphertext;
}
*/

void decrypt_aes(char* initial_data){
    //read key from file
    fptr = fopen("main.axf", "rb");
    char AES_KEY_A[32];
    fgets(AES_KEY_A, 32, fptr);
    char AES_KEY_B[32];
    fgets(AES_KEY_B, 32, fptr);
    fclose(fptr); 
    
    //maybe need to initialize hash parameters
    /*
    ;1. decrypt A 
    2. extract IV (16 bytes)
    3. decrypt B
    4. append data to perform checks
    */
    
    // br_gcm_context gcm_context;
    // br_block_ctr_class ctr_class;
    // br_ghash gcm_hash;
    // br_gcm_init(&gcm_context, &ctr_class, gcm_hash);
    // // br_gcm_reset(&gcm_context, AES_KEY_A, strlen(AES_KEY_A));
    // br_gcm_run(&gcm_context, 0, data, strlen(data));

    // br_aes_ct_cbcdec_keys cbc_context;
    // br_aes_ct_cbcdec_init(&cbc_context, AES_KEY_B, strlen(AES_KEY_B));
    
    // : change from bearssl to beaver ssl 
    data[strlen(initial_data)];
    for (size_t i = 0; i < strlen(initial_data); i++)
    {
        data[i] = initial_data[i];
    }
    

    char nonce[16];
    for (size_t i = 0; i < 16; i++)
    {
        nonce[i] = data[FLASH_PAGESIZE+i];
    }
    char aad[16];//aad iv is created like a key so it is in the secret file
    
    char tag[128];
    for (size_t i = 0; i < 128; i++)
    {
        tag[i] = data[FLASH_PAGESIZE+i];
    }

    gcm_decrypt_and_verify(AES_KEY_A, nonce, data, strlen(data), aad, strlen(aad), tag);
    
    //AES-CBC
    char iv_cbc[16];
    for (size_t i = 0; i < 16; i++)
    {
        iv_cbc[i] = iv_cbc[FLASH_PAGESIZE+i];
    }
    aes_decrypt(AES_KEY_B, iv_cbc, data, strlen(data));
    
    int count;
    char fw_size[2];
    for (size_t i = count; i < count+2; i++)
    {
        fw_size[i] = data[i];
    }
    uint16_t fw_size_int = fw_size[0] + (fw_size[1] << 8);
    
    count += 2;
    char fw_ver[2];
    for (size_t i = count; i < count+2; i++)
    {
        fw_ver[i] = data[i];
    }

    count += 2;
    char msg_size[2];
    for (size_t i = count; i < count+2; i++)
    {
        msg_size[i] = data[i];
    }

    count += 2;
    uint16_t msg_size_int = msg_size[0] + (msg_size[1] << 8);
    char msg_data[msg_size_int];
    for (size_t i = count; i < count+msg_size_int; i++)
    {
        msg_data[i] = data[i];
    }
    
    count += msg_size_int;
    char fw_data[fw_size_int];
    for (size_t i = count; i < count+fw_size_int; i++)
    {
        fw_data[i] = data[i];
    }
    
    count+=fw_size_int;
    char hash[32];
    for (size_t i = count; i < count+32; i++)
    {
        hash[i] = data[i];
    }

    count += 32;
    char iv[16];
    for (size_t i = count; i < count+16; i++)
    {
        hash[i] = data[i];
    }
    
}

// CHECK SUM 
unsigned char calculate_custom_checksum(const unsigned char* data, uint32_t data_len) {
    unsigned int checksum = 0xFF; // Initialize checksum to 0xFF

    // Calculate checksum each custom algorithm
    for (uint32_t i = 0; i < data_len; i++) {
        if (i == 0 , i == 1 , i == 2) {
            continue; // Skip the start delimiter and length bytes
        }
        checksum += data[i];
    }

    return (unsigned char)(checksum & 0xFF); // Keep only the lowest 8 bits
}

//verifying if checksum for frames are correct
bool verify_frame(const unsigned char* frame_data, uint32_t frame_len){
    if (frame_len < 2) {
        return false;//we return false because frame is too small for checksum
    }

    //checks the payload
    unsigned char calculate_checksum = calculate_custom_checksum(frame_data, frame_len-1);

    //check the last digit
    return (calculate_checksum == frame_data[frame_len - 1]);
}


/*
 * Load initial firmware into flash
 */
void load_initial_firmware(void){

    if (*((uint32_t *)(METADATA_BASE)) != 0xFFFFFFFF){
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

    for (i = 0; i < size / FLASH_PAGESIZE; i++){
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), initial_data + (i * FLASH_PAGESIZE), FLASH_PAGESIZE);
    }

    /* At end of firmware. Since the last page may be incomplete, we copy the initial
     * release message into the unused space in the last page. If the firmware fully
     * uses the last page, the release message simply is written to a new page.
     */

    uint16_t rem_fw_bytes = size % FLASH_PAGESIZE;
    if (rem_fw_bytes == 0){
        // No firmware left. Just write the release message
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)initial_msg, msg_len);
    }else{
        // Some firmware left. Determine how many bytes of release message can fit
        if (msg_len > (FLASH_PAGESIZE - rem_fw_bytes)){
            rem_msg_bytes = msg_len - (FLASH_PAGESIZE - rem_fw_bytes);
        }else{
            rem_msg_bytes = 0;
        }

        // Copy rest of firmware
        memcpy(temp_buf, initial_data + (i * FLASH_PAGESIZE), rem_fw_bytes);
        // Copy what will fit of the release message
        memcpy(temp_buf + rem_fw_bytes, initial_msg, msg_len - rem_msg_bytes);
        // Program the final firmware and first part of the release message
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), temp_buf, rem_fw_bytes + (msg_len - rem_msg_bytes));

        // If there are more bytes, program them directly from the release message string
        if (rem_msg_bytes > 0){
            // Writing to a new page. Increment pointer
            i++;
            program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)(initial_msg + (msg_len - rem_msg_bytes)), rem_msg_bytes);
        }
    }
}

/*
 * Load the firmware into flash.
 * Receieve all frames
 * Decrypt with GCM
 * Get version , size, message, iv
 * Decrypt rest with CBC
 * Get firmware and hash
 */
void load_firmware(void){
    int frame_length = 0;
    int read = 0;
    uint32_t rcv = 0;

    uint32_t data_index = 0;
    uint32_t page_addr = FW_BASE;
    uint32_t version = 0;
    uint32_t size = 0;

    // Get size as 16 bytes 
    rcv = uart_read(UART1, BLOCKING, &read);
    size = (uint32_t)rcv;
    rcv = uart_read(UART1, BLOCKING, &read);
    size |= (uint32_t)rcv << 8;

    uart_write_str(UART2, "Received Firmware Size: ");
    uart_write_hex(UART2, size);
    nl(UART2);

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

    uart_write(UART1, OK); // Acknowledge the metadata.

    /* Loop here until you can get all your characters and stuff */
    while (1){
        // Get start frame endian short
        rcv = uart_read(UART1, BLOCKING, &read);
        int start_short = (int)rcv;
        rcv = uart_read(UART1, BLOCKING, &read);
        start_short |= (int)rcv << 8;

        if (start_short!=1){
            uart_write(UART1, ERROR); // Reject the metadata.
            SysCtlReset();            // Reset device
            return;
        }

        // Get two bytes for the length.
        rcv = uart_read(UART1, BLOCKING, &read);
        frame_length = (int)rcv << 8;
        rcv = uart_read(UART1, BLOCKING, &read);
        frame_length += (int)rcv;

        // Get the 256 length data
        for (int i = 0; i < frame_length; ++i){
            data[data_index] = uart_read(UART1, BLOCKING, &read);
            data_index += 1;
        } 

        // Get the 32 length checksum
        for (int i = 0; i < 32; ++i){
            data[data_index] = uart_read(UART1, BLOCKING, &read);
            data_index += 1;
        } 

        uart_write(UART1, OK); // Acknowledge the frame.
    }                          // while(1)
}

long program_flash(uint32_t page_addr, unsigned char *data, unsigned int data_len){
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase(page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE){
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, page_addr, num_full_bytes);
        if (ret != 0){
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++){
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++){
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, page_addr + num_full_bytes, 4);
    }else{
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, page_addr, data_len);
    }
}

void boot_firmware(void){
    // compute the release message address, and then print it
    uint16_t fw_size = *fw_size_address;
    fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
    uart_write_str(UART2, (char *)fw_release_message_address);

    // Boot the firmware
    __asm(
        "LDR R0,=0x10001\n\t"
        "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len) {
    for (uint8_t * cursor = start; cursor < (start + len); cursor += 1) {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9) {
            right_nibble += 0x37;
        } else {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9) {
            left_nibble += 0x37;
        } else {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';
        
        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}