
rule kfc8_131a9389c4420b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=kfc8.131a9389c4420b32"
     cluster="kfc8.131a9389c4420b32"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mydoom email doubleextension"
     md5_hashes="['5c811d0deda3df712fa8c9ad9b3a9977294cc55a','9413aa6c552e1e414c5ed2e193e098ea1515f23f','f630e952eb915a843dea9fa4d0701592e48884d4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=kfc8.131a9389c4420b32"

   strings:
      $hex_string = { 845c30c2a45e9a31af2d87064beab0ac999d37183658842e8d0049543388b97809fb10b2b695586ea352434f24043e2768a5776234077a127b2f92b9da19ef17 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
