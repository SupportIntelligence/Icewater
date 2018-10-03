
rule k2318_2512d38bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2512d38bc6220b32"
     cluster="k2318.2512d38bc6220b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['3fd8b43f2b3f43399ffe6897b7ee45cc1404224e','7e18c7d57e47c94b652bac2f31b5a370d625444c','5f1409c59723c394c94f239ef144b57e5a29bd44']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2512d38bc6220b32"

   strings:
      $hex_string = { 626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
