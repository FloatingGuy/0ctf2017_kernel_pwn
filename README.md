# 0ctf2017_kernel_pwn
0ctf2017 Kernel Pwnable - note

SMEP + KASLR + security checks on the buffer address for read/write

Two bugs:
1. uninitialized heap memory
2. race condition between edit the time of a note and delete a note
plus no buffer address check when deleting a note

Unintended bug:
if copy_from_user for note buffer in add_note fails, put_note is called while the next/prev pointers of the note are not initialized in alloc_note
