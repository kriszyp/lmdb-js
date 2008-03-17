/*
 * Copyright 2008, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "LdifReader.h"
#include "LDAPMessage.h"
#include "LDAPEntry.h"
#include "LDAPAttributeList.h"
#include "LDAPAttribute.h"
#include "LDAPUrl.h"
#include "debug.h"

#include <string>

#include <sasl/saslutil.h> // For base64 routines

LdifReader::LdifReader( std::istream &input ) : m_ldifstream(input)
{
    DEBUG(LDAP_DEBUG_TRACE, "<> LdifReader::LdifReader()" << std::endl);
}

int LdifReader::readNextRecord()
{
    DEBUG(LDAP_DEBUG_TRACE, "-> LdifReader::readRecord()" << std::endl);
    std::string line;
    std::string type;
    std::string value;
    int numLine = 0;
    int recordType = 0;
    m_currentRecord.clear();

    while ( !this->getLdifLine(line) && line != "" )
    {
        DEBUG(LDAP_DEBUG_TRACE, "  Line: " << line << std::endl );
        int rc = this->splitLine(line, type, value);
        if ( rc )
        {
            DEBUG(LDAP_DEBUG_TRACE, " Error while splitting ldif line" 
                    << std::endl);
        }
        if ( numLine == 0 )
        {
            if ( type == "dn" ) // Record should start with the DN ...
            {
                DEBUG(LDAP_DEBUG_TRACE, " Record DN:" << value << std::endl);
            }
            else if ( type == "include" ) // ... or it might be an "include" line
            {
                DEBUG(LDAP_DEBUG_TRACE, " Include directive: " << value << std::endl);
                //this->readIncludeLine(value);
            }
            else
            {
                DEBUG(LDAP_DEBUG_TRACE, " Record doesn't start with a DN" 
                            << std::endl);
                return 0;
            }
        }
        if ( numLine == 1 ) // might contain "changtype" to indicate a change request
        {
            if ( type == "changetype" ) 
            {
                if ( value == "modify" )
                {
                    recordType = LDAPMsg::MODIFY_REQUEST;
                }
                else if ( value == "add" )
                {
                    recordType = LDAPMsg::ADD_REQUEST;
                }
                else if ( value == "delete" )
                {
                    recordType = LDAPMsg::DELETE_REQUEST;
                }
                else if ( value == "modrdn" )
                {   
                    recordType = LDAPMsg::MODRDN_REQUEST;
                }
                else
                {
                    DEBUG(LDAP_DEBUG_TRACE, " Unknown change request <" << value << ">" << std::endl);
                    return 0;
                }
            }
            else
            {
                recordType = LDAPMsg::SEARCH_ENTRY;
            }
        }
        m_currentRecord.push_back(std::pair<std::string, std::string>(type, value));
        numLine++;
    }
    DEBUG(LDAP_DEBUG_TRACE, "<- LdifReader::readRecord()" << std::endl);
    m_curRecType = recordType;
    return recordType;
}

LDAPEntry LdifReader::getEntryRecord()
{
    if ( m_curRecType != LDAPMsg::SEARCH_ENTRY )
    {
        // Error
    }
    std::list<std::pair<std::string, std::string> >::const_iterator i = m_currentRecord.begin();
    LDAPEntry resEntry(i->second);
    i++;
    LDAPAttribute curAttr(i->first);
    LDAPAttributeList *curAl = new LDAPAttributeList();
    for ( ; i != m_currentRecord.end(); i++ )
    {
        if ( i->first == curAttr.getName() )
        {
            curAttr.addValue(i->second);
        }
        else
        {
            if ( curAl->getAttributeByName( i->first ) ) 
                    // Attribute exists already -> Syntax Error
            {
                // Error
            }
            else
            {
                curAl->addAttribute( curAttr );
                curAttr = LDAPAttribute( i->first, i->second );
            }
        }
    }
    curAl->addAttribute( curAttr );
    resEntry.setAttributes( curAl );
    return resEntry;
}

int LdifReader::getLdifLine(std::string &ldifline)
{
    DEBUG(LDAP_DEBUG_TRACE, "-> LdifReader::getLdifLine()" << std::endl);

    if ( ! getline(m_ldifstream, ldifline) )
    {
        return -1;
    }

    while ( m_ldifstream &&
        (m_ldifstream.peek() == ' ' || m_ldifstream.peek() == '\t'))
    {
        std::string cat;
        m_ldifstream.ignore();
        getline(m_ldifstream, cat);
        ldifline += cat;
    }

    DEBUG(LDAP_DEBUG_TRACE, "<- LdifReader::getLdifLine()" << std::endl);
    return 0;
}

int LdifReader::splitLine(const std::string& line, 
            std::string &type,
            std::string &value)
{
    std::string::size_type pos = line.find(':');
    if ( pos == std::string::npos )
    {
        DEBUG(LDAP_DEBUG_ANY, "Invalid LDIF line. Not `:` separator" 
                << std::endl );
        return -1;
    }
    type = line.substr(0, pos);
    if ( pos == line.size() )
    {
        // empty value
        value = "";
        return 0;
    }
    pos++;
    char delim = line[pos];
    if ( delim == ':' || delim == '<' )
    {
        pos++;
    }
    for( ; pos < line.size() && isspace(line[pos]); pos++ )
    { /* empty */ }

    value = line.substr(pos);

    if ( delim == ':' )
    {
        // Base64 encoded value
        DEBUG(LDAP_DEBUG_TRACE, "  base64 encoded value" << std::endl );
        char outbuf[value.size()];
        int rc = sasl_decode64(value.c_str(), value.size(), 
                outbuf, value.size(), NULL);
        if( rc == SASL_OK )
        {
            value = std::string(outbuf);
        }
        else if ( rc == SASL_BADPROT )
        {
            value = "";
            DEBUG( LDAP_DEBUG_TRACE, " invalid base64 content" << std::endl );
            return -1;
        }
        else if ( rc == SASL_BUFOVER )
        {
            value = "";
            DEBUG( LDAP_DEBUG_TRACE, " not enough space in output buffer" 
                    << std::endl );
            return -1;
        }
    }
    else if ( delim == '<' )
    {
        // URL value
        DEBUG(LDAP_DEBUG_TRACE, "  url value" << std::endl );
        return -1;
    }
    else 
    {
        // "normal" value
        DEBUG(LDAP_DEBUG_TRACE, "  string value" << std::endl );
    }
    DEBUG(LDAP_DEBUG_TRACE, "  Type: <" << type << ">" << std::endl );
    DEBUG(LDAP_DEBUG_TRACE, "  Value: <" << value << ">" << std::endl );
    return 0;
}

std::string LdifReader::readIncludeLine( const std::string& line ) const
{
    std::string::size_type pos = sizeof("file:") - 1;
    std::string scheme = line.substr( 0, pos );
    std::string file;

    // only file:// URLs supported currently
    if ( scheme != "file:" )
    {
        DEBUG( LDAP_DEBUG_TRACE, "unsupported scheme: " << scheme 
                << std::endl);
    }
    else if ( line[pos] == '/' )
    {
        if ( line[pos+1] == '/' )
        {
            pos += 2;
        }
        file = line.substr(pos, std::string::npos);
        DEBUG( LDAP_DEBUG_TRACE, "target file: " << file << std::endl);
    }
    return file;
}
