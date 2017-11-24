
rule m3e9_4d464c5c132d2f14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4d464c5c132d2f14"
     cluster="m3e9.4d464c5c132d2f14"
     cluster_size="17"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys changeup"
     md5_hashes="['1b844aa9d20295d15c28a8c60f786cc9','5815f6f14a87c056bc64c6a2d55ef7d0','e6f23f8b7aa1f610e88aebe9049126dd']"

   strings:
      $hex_string = { 877cd6a89ff3b6b2f1bdc2efbcc2f3bdbffbc0bef2b5b7f59390dc7b71b8c4c1e8aad8ea6ce7ee2fe0f80ccafc0bbafd18adf41ca3f13092e15990cb86a3bea4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
