
rule k2321_1b1b194ad89b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1b1b194ad89b0912"
     cluster="k2321.1b1b194ad89b0912"
     cluster_size="45"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt symmi gamarue"
     md5_hashes="['068140dde7ceca58e8c2fe2fb07b4836','0f20516be5ac518de1db5db48708cf81','66a51e91a388a6db7ead98e88738f201']"

   strings:
      $hex_string = { 34c6264b53f20e7d36a0b4b662c1b2e925441e0f2c69b0ee28c43c11b55c29aa503b70669b5d6aa13521859eb3d08fb22db193f5083709187707c58aef1a0c3d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
