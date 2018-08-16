#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sstream>
#include <algorithm>
#include <map>

using namespace std;

void error(char *);

bool init(char *);
bool filter(char *);
bool gethost(char *, char *);
