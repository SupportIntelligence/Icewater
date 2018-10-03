
rule n26c0_79b9e5a4db92f10e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.79b9e5a4db92f10e"
     cluster="n26c0.79b9e5a4db92f10e"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ddyr chapak malicious"
     md5_hashes="['2a349c85749ffec9ed4822e6cc5853f64247c5bc','9b32f3b4d04f3c688326144cbbf67f8c4a65e36a','0043a44281be7592b4f060064a1735a87df8d6d1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.79b9e5a4db92f10e"

   strings:
      $hex_string = { cc803e2974178d4df4e8280300000fb6c0f7d81bc083e0fd83c007eb036a04585b5f5e8be55dc38bff558bec53568b750833db578b7d0c8bd38a063a822c7a43 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
