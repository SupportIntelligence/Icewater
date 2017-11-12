
rule m3e9_619c3ac1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.619c3ac1cc000b16"
     cluster="m3e9.619c3ac1cc000b16"
     cluster_size="376"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack virut"
     md5_hashes="['006f55382818d5e75e6ac237c64aadd8','0129caf929498bde364578edf19c4b18','19a5a2f19adfe64313f0a80a7368e263']"

   strings:
      $hex_string = { 494f36c822410fbafb33e8acd425c19ead179a90860973825ffb4b7438ed246611dffd58ead1d64ac3c3af3c9cb5882e75a761204e993a12278b1304007decf6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
