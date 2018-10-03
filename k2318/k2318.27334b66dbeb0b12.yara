
rule k2318_27334b66dbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27334b66dbeb0b12"
     cluster="k2318.27334b66dbeb0b12"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['831adac41ba27c6a75b610f0d6028b80f754ac02','229877e026b13f114b55c1632bb55e3d72850869','1f17b23e9167f24aa7aee0508d8026084a3e91bb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27334b66dbeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
