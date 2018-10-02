
rule o26c0_539c39a1ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.539c39a1ca000b32"
     cluster="o26c0.539c39a1ca000b32"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="midie kryptik malicious"
     md5_hashes="['8bbf70332f516ea683999023440b59915cb2d8cd','8615e99c5e5994271731c2e58660cde35181008f','1a0f7c2842b492b9fa56ec2e7049b2ae551d4b88']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.539c39a1ca000b32"

   strings:
      $hex_string = { 0803f8897e348b4e2885c97f068bc30bc2743a6a00ff75108d41ff5253894628e83451010080c130895dfc8bd880f9397e11807d14000f94c0fec824e004612c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
