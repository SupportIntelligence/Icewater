
rule j3e9_24a9e225d6bb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.24a9e225d6bb1912"
     cluster="j3e9.24a9e225d6bb1912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="selfdel generickd upatre"
     md5_hashes="['006cb5c4465cd9ba70a37e32902fa123','72febc4d7ae4e2165613f6176f589507','913d9d9e8a57b57ca42fe2439eaa31e9']"

   strings:
      $hex_string = { 7e0dbf1e128274973ba65114df636e8d423f0ece4f9a85f5a063a52fa03d7b0b8ed5207fbb6e537250cff3fa4027945ff82b6c46f99103fb6f47b9ef35d1d461 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
