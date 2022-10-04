/*
 * mail.h
 */

#ifndef __MAIL_H__
#define __MAIL_H__

typedef struct {

	char sender[256];
	size_t contentsize;
	size_t sigsize;
} MAIL;

#endif