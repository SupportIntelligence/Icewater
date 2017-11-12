
rule m3e9_3a155a6d8deb0b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a155a6d8deb0b14"
     cluster="m3e9.3a155a6d8deb0b14"
     cluster_size="970"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['010d8157ec1542b8796569e976db648c','0193fad95800ae672d4acc0b66459806','0ab4bdedc546939676fe7ed28890f25d']"

   strings:
      $hex_string = { 0e4b1d8ddebca0bcd0c8106e9e9278d45f2161992b60bccd829f36673cfe40878314259fb424e96027bb8069140f48c62e8747854cbaca00d3b83dd95cbb40ac }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
