/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef STRING_LIST_H
#define STRING_LIST_H

#include <string>
#include <list>
typedef list<string> ListType;

class StringList{
    typedef ListType::const_iterator const_iterator;
   
    private:
        ListType m_data;

    public:
        StringList();
        StringList(const StringList& sl);
        StringList(char** values);
        ~StringList();
    
        char** toCharArray() const;
        void add(const string& value);
        size_t size() const;
        const_iterator begin() const;
        const_iterator end() const;
        void clear(); 
};
#endif //STRING_LIST_H
