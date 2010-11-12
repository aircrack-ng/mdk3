#ifndef HAVE_LINKEDLIST_H
#define HAVE_LINKEDLIST_H

#include "mac_addr.h"

struct clist
{
  unsigned char *data;
  int data_len;
  int status;
  struct clist *next;
};

struct clistwidsap
{
  struct ether_addr bssid;
  int channel;
  unsigned char capa[2];
  struct clistwidsap *next;
};

struct clistwidsclient
{
  struct ether_addr mac;
  char status; //0=ready 1=authed 2=assoced
  int retry;
  struct clistwidsclient *next;
  unsigned char *data;
  int data_len;
  struct clistwidsap *bssid;
};

//All these calls are thread-safe via a single pthrea_mutex!

struct clist *search_status(struct clist *c, int desired_status);

struct clistwidsclient *search_status_widsclient(struct clistwidsclient *c, int desired_status, int desired_channel);

struct clist *search_data(struct clist *c, unsigned char *desired_data, int data_len);

struct clistwidsap *search_bssid(struct clistwidsap *c, struct ether_addr desired_bssid);

struct clistwidsclient *search_client(struct clistwidsclient *c, struct ether_addr mac);

struct clist *add_to_clist(struct clist *c, unsigned char *data, int status, int data_len);

struct clistwidsap *add_to_clistwidsap(struct clistwidsap *c, struct ether_addr bssid, int channel, unsigned char *capa);

struct clistwidsclient *add_to_clistwidsclient(struct clistwidsclient *c, struct ether_addr mac, int status, unsigned char *data, int data_len, struct clistwidsap *bssid);

#endif
