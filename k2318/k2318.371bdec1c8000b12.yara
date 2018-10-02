
rule k2318_371bdec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.371bdec1c8000b12"
     cluster="k2318.371bdec1c8000b12"
     cluster_size="943"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['0e1f7d7a2158a17d8d450984986dc5e59b8a97e9','f9dd70a5cddde1768cc715d8b5aa324a34d18b00','8f27e42e6f0ab6a0a637effdd99820bc737d1aa1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.371bdec1c8000b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
