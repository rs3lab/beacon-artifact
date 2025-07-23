#define __hide_section_warning(section_string)    \
    __asm__ (".section " section_string "\n.string \"\rLinked Succesfully                          \"\n\t.previous");

#define hide_warning(symbol) \
  __hide_section_warning (".gnu.warning." #symbol) 

hide_warning(getgrouplist)
hide_warning(getgrgid_r)
hide_warning(getgrnam_r)
hide_warning(getpwnam_r)
hide_warning(getpwuid_r)
hide_warning(getaddrinfo)