
rule pfc8_311ca54bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.311ca54bc6220b12"
     cluster="pfc8.311ca54bc6220b12"
     cluster_size="39"
     filetype = "ASCII text"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos triada ransomkd"
     md5_hashes="['015120467671f552936cca49e6d60242','0588592ef6b446bc2a0e06a433c15caa','53accf6489280efd204c146c157ad822']"

   strings:
      $hex_string = { bffcba7895c0b408fe7c067fffde23e7a4f51a2bbd25917e50485f77aaf8dcd68aeee27a6eb6d43bb782a9e49ccc1563266b7519d3c214f157cdc852c13d17fa }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
