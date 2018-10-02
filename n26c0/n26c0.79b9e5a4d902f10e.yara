
rule n26c0_79b9e5a4d902f10e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.79b9e5a4d902f10e"
     cluster="n26c0.79b9e5a4d902f10e"
     cluster_size="52"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious filerepmalware kryptik"
     md5_hashes="['aab4f8b9862e387c9612037dd5822b34dbfe1bb1','44ac9b59509a2f713063a7699b525151a926aea4','9301c688d7913f8656eb7a14d2916c02ded0cc2a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.79b9e5a4d902f10e"

   strings:
      $hex_string = { cc803e2974178d4df4e8280300000fb6c0f7d81bc083e0fd83c007eb036a04585b5f5e8be55dc38bff558bec53568b750833db578b7d0c8bd38a063a822c7a43 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
