
rule m26bb_15c6bae1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.15c6bae1c2000932"
     cluster="m26bb.15c6bae1c2000932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious virut virtu"
     md5_hashes="['f1e4270526361819e05ce7fa1adf1579333e07f3','60b055e9993485ea7846d2de86b6032016c8a616','7015dd50691fa9703a682d2de5709a3de11e4b48']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.15c6bae1c2000932"

   strings:
      $hex_string = { 8a29399b380a4bb1df25f002b85ad8e3b328b005dccf43b458ab69048b56738cfd8c948818524e870399610347ebb6e90c15e1d45b44408fe998cf40137a4117 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
