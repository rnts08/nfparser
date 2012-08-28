nfparser
========

in-house script to pull formatteddata out of nfcapd-files

NOTE: This is probably not perfect, especially the createFileName()-part since it plays with hours and minutes 
      generate a filename with lag from nfcapd. I have no idea what happends at 00:00 with that code, but since
      I use it between 9.00 and 18.00 I dont really care. =)