
rule n3e9_4b9e6848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b9e6848c0000b12"
     cluster="n3e9.4b9e6848c0000b12"
     cluster_size="46"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre qvod"
     md5_hashes="['0cedc240c651daa134141a527218aca5','211efcf51a492444bba6d3291d318104','b0878fb08e7765f07494b44ebee6ffb2']"

   strings:
      $hex_string = { 917184498626aad31a0ea48093771f50ebd9e1a7fe2a5c17b8adfb67ac56369587af358f90864538bc972db39f362629f3b856967b163046b488734c4d24725c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
