
rule n26ef_51332a49c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26ef.51332a49c0000932"
     cluster="n26ef.51332a49c0000932"
     cluster_size="949"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="runbooster cunh malicious"
     md5_hashes="['83274a7dabe2df7afd6e04cf40eaa5ad6b7dd4b1','f538549b61e7c7a966dad4c4686fd2ae7288510f','61c7569f9af6d2a49e93d2d7fc0da2366fd4ae82']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26ef.51332a49c0000932"

   strings:
      $hex_string = { 4c89b42408000100418d50024533f63bd573270f1f008d42ff803c180d7506803c1a0a740b41ffc0ffc23bd572e8eb0a458bf0452bf74183c60365488b042558 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
