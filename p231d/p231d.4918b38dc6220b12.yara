
rule p231d_4918b38dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p231d.4918b38dc6220b12"
     cluster="p231d.4918b38dc6220b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="riskware smspay heepay"
     md5_hashes="['eda8b3f60426ab1693d57db26bcc27a2bd232db6','c61d19c9a549f4f3a16ac1d42f36d1969a10daf2','2cc76afe45a66c6ff2bb7e6708d7b171fea3f4da']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p231d.4918b38dc6220b12"

   strings:
      $hex_string = { 4af987c0407f0ff8673e17bd9a632a748de7c79f5de0aa57be097ad81f0ec9940b53ccc4b227a699291962d11da5b572fc6148add68e22b66a0a3a1c027cefc5 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
