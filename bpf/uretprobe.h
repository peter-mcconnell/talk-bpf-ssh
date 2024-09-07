#ifndef __URETPROBE_H__
#define __URETPROBE_H__

typedef struct _event_t {
    int  pid;
    char comm[16];
    char username[80];
    char password[80];
} event_t;

typedef struct pam_handle
{
  char *authtok;
  unsigned caller_is;
  void *pam_conversation;
  char *oldauthtok;
  char *prompt;
  char *service_name;
  char *user;
} pam_handle_t;

#endif
