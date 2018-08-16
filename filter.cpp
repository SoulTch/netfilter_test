#include "netfilter.h"

#define LIST_SIZE 256
#define BUF_SIZE 2000

class TreeNode {
public:
    bool fin;
    TreeNode *next[LIST_SIZE];
    
    TreeNode() : fin(false) {
        for (int i = 0; i < LIST_SIZE; i++) {
            next[i] = NULL;
        }
    }
};

TreeNode *root;

bool init(char *filename) {
    FILE *fp = (FILE *)fopen(filename, "r");
    if (fp == NULL) return false;

    root = new TreeNode();

    char buf[BUF_SIZE + 10];

    while(fgets(buf, BUF_SIZE + 10, fp) != NULL) {
        size_t l = strnlen(buf, BUF_SIZE + 10);
		if (buf[l - 1] == '\n') l--;
        if (l > BUF_SIZE || l <= 0) return false;

        TreeNode *c = root;
        for (int i = l - 1; i >= 0; i--) {
			if ('A' <= buf[i] && buf[i] <= 'Z') buf[i] |= ('A' ^ 'a');
            if (c->next[buf[i]] == NULL) {
                c->next[buf[i]] = new TreeNode();
            }
            c = c->next[buf[i]];
        }
        c->fin = true;
    }

    return true;
}

bool filter(char *p) {
    TreeNode *c = root;
	char *a = p;
	for (;*a;a++);

    for (a--; a >= p; a--) {
        c = c->next[*a];
        
        if (c == NULL) break;
        if (c->fin) {
            if (a == p || *(a - 1) == '.') {
                return true;
            }
        }
    }

    return false;
}

string trim(string s) {
	s.erase(s.begin(), find_if(s.begin(), s.end(), [](int ch) {
		return !isspace(ch);
	}));
	s.erase(find_if(s.rbegin(), s.rend(), [](int ch) {
		return !isspace(ch);
	}).base(), s.end());
	return s;
}

bool gethost(char *s, char *r) {
	istringstream resp(s);
	string header;
	string::size_type index;
	while (getline(resp, header) && header != "\r") {
		index = header.find(':', 0);
		if(index != string::npos) {
			if (trim(header.substr(0, index)) == "Host") {
				strcpy(r, trim(header.substr(index + 1)).c_str());
				return true;
			}
		}
	}

	return false;
}











