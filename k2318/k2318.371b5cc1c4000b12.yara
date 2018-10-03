
rule k2318_371b5cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.371b5cc1c4000b12"
     cluster="k2318.371b5cc1c4000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['1774e5d6df606488731482336f67f1892b1083b5','9c8ef94a6e88f083167d17b90ed3ad2fb05bf840','1e21f76be0030cee95db06592083f5e535a2f489']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.371b5cc1c4000b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
