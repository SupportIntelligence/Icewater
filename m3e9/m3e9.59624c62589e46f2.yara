
rule m3e9_59624c62589e46f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.59624c62589e46f2"
     cluster="m3e9.59624c62589e46f2"
     cluster_size="501"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef autorun"
     md5_hashes="['00e21c254408b2bd7615bff7946d64dc','01714e81d8ff07f9245b86d8a30731c3','169f1c84483409721ae72449c0d44afe']"

   strings:
      $hex_string = { 0085858200888985008c8c89008f908e0091928e008f8597009292910094959100979894009a9a9400999998009c9c9a009d9d9c00a7818d00b3838900b09999 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
