
rule m26bb_13624ec344000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.13624ec344000916"
     cluster="m26bb.13624ec344000916"
     cluster_size="44"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore alphaeon malicious"
     md5_hashes="['5ce524000efd2be213b5161c571ccfa67f327527','d1ce7e3072cb39214baab33b430a18274a4bb8ca','5d5d87bede00da895cffb8e50f8e715c31ed3f16']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.13624ec344000916"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c74104ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
