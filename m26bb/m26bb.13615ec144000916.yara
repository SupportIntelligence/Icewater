
rule m26bb_13615ec144000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.13615ec144000916"
     cluster="m26bb.13615ec144000916"
     cluster_size="207"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore dealply malicious"
     md5_hashes="['51364db9d45f8a83206689d614134b0642d239cd','194fd63cd481b3025bc3f68bf0a3d76ec452e737','507df27aa2cc50c302eb35ca982af1ccbae60c26']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.13615ec144000916"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c74104ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
