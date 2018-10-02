
rule k2318_3731412eba210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3731412eba210b12"
     cluster="k2318.3731412eba210b12"
     cluster_size="205"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['62055ba1b628deaa98a687cb2fb1f78c288af632','200b6cdd95ddd618ff3b82d8290d441f5c152d9c','6b433ddf5e64327251a674503f4e540fa777e7ed']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3731412eba210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
