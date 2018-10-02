
rule n231d_11bc6a12d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.11bc6a12d6c30912"
     cluster="n231d.11bc6a12d6c30912"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddad androidos hiddenads"
     md5_hashes="['ad721f3f0bbb0b3418a495322bc3f56ecf461b5a','289d775684d15e05a26606a0444eada39fee928e','9d2ca24d92f2b99d51764664c94a6a715b5a6cf1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.11bc6a12d6c30912"

   strings:
      $hex_string = { 5300012e25035ddaff733307dfe34ec00b5e15e222e1c1082187113677dbfcfb0688e58ad92a8ec80289efcd9d4c97e92b52e64ab46dadcf8517f80f35fd10b9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
