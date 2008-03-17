/*
 * Copyright 2008, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDIF_READER_H
#define LDIF_READER_H

#include <LDAPEntry.h>
#include <iosfwd>
#include <list>

typedef std::list< std::pair<std::string, std::string> > LdifRecord;
class LdifReader
{
    public:
        LdifReader( std::istream &input );
        int readNextRecord();
        LDAPEntry getEntryRecord();

    private:
        int getLdifLine(std::string &line);

        int splitLine(const std::string& line, 
                    std::string &type,
                    std::string &value );

        std::string readIncludeLine( const std::string &line) const;

        std::istream &m_ldifstream;
        LdifRecord m_currentRecord;
        int m_curRecType;
};

#endif /* LDIF_READER_H */
