
rule m26bb_136e7ec148001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.136e7ec148001116"
     cluster="m26bb.136e7ec148001116"
     cluster_size="217"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore dealply malicious"
     md5_hashes="['106bd3e31436396841b3d4df0f6340283d79ee2e','ae101d95bcb79cafbc8b34a230e3ab688a42ab1a','85eca42b5c9a3bb0f41495d42ca5ac13bb4264dd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.136e7ec148001116"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c74104ed }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
