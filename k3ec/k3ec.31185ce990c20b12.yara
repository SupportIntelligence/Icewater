
rule k3ec_31185ce990c20b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.31185ce990c20b12"
     cluster="k3ec.31185ce990c20b12"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious engine moderate"
     md5_hashes="['13cf9f732cd479dbbec9777b34386b1f','3fda8db10ee6800d15b0c0cd9fa5c336','e7dded9d529828ac687dd27a4023a21e']"

   strings:
      $hex_string = { 01000000537461636b2061726f756e6420746865207661726961626c65202700272077617320636f727275707465642e00000000546865207661726961626c65 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
