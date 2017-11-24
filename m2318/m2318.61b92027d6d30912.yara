
rule m2318_61b92027d6d30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.61b92027d6d30912"
     cluster="m2318.61b92027d6d30912"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0d9ef4c0eebcbbd8acd3cc3de059aa5f','22eaf401ef322e2b471cb4132930018c','f0f3a571dafcc354d7edb241f905efb7']"

   strings:
      $hex_string = { 31383233374446333432434631354236333741353638414639394230463444454335393142444132383030444632433546364543453933454241354438433430 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
