#ifndef __NETAPP_H
#define __NETAPP_H

/**
 * The strings will be compared against fnode->filename
 * which is the file that symbolic can point to, if any.
 * Example:
 *
 *       (symlink)           (executable)
 *  /usr/bin/black.nose -> /bin/blacknose
 *
 *  The names below are just examples and can be
 *  modified and/or extended at will
 */
static const char *netapp_list[] = {
    "whitenose", "pinknose", "rednose", "blacknose",
    "greynose", "purplenose", "bluenose", NULL
};

#endif
