
rule m3f9_331e731baea90912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.331e731baea90912"
     cluster="m3f9.331e731baea90912"
     cluster_size="18"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery malicious pemalform"
     md5_hashes="['0875d8213208707da652654ecf5e08e9','2140de0def88265f290f02c05451c744','ef2d7c434cf85bd38a5ef18833cc9999']"

   strings:
      $hex_string = { 93369a36b537e437e837ec370838103816382f3835388f389638a938b638b439b839bc39ed39f839fe39183a1e3a503a723a793a913bb83bbc3bc03bd53b053c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
