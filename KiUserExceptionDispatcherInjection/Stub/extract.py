import pefile
import argparse

if __name__ in '__main__':
    try:
        parser = argparse.ArgumentParser( description = 'extracts bytes from a PE' );
        parser.add_argument( '-f', required = True, help = 'path to the source executable', type = str );
        parser.add_argument( '-o', required = True, help = 'path to store the output raw binary', type = str );
        option = parser.parse_args();

        marker = b'\x70\x64\x61\x74\x61\x00\x00';
        textSection = pefile.PE( option.f ).sections[0].get_data();
        scBytes = textSection[textSection.find( marker ) + len( marker ) : textSection.find( b'\xC3' ) + 1];

        print( '[ + ] extracted {} bytes'.format( len( scBytes ) ) );
        print( '[ + ] stub:\n unsigned char stub[] = {{ {} }};'.format( ', '.join( f'0x{b:02X}' for b in scBytes ) ) );

        f = open( option.o, 'wb+' );
        f.write( scBytes );
        f.close();
    except Exception as e:
        print( '[!] error: {}'.format( e ) );
