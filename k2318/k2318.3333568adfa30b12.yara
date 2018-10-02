
rule k2318_3333568adfa30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3333568adfa30b12"
     cluster="k2318.3333568adfa30b12"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['79dd84baa163bd07ded3a6df7279d389ad310b1b','372c4ed42d74aa12308da3d1f354ed0ce14d82eb','a102807d6c2bfda6f0c55213eb3a6bf72b2e0f18']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3333568adfa30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
