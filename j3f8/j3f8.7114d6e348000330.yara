
rule j3f8_7114d6e348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7114d6e348000330"
     cluster="j3f8.7114d6e348000330"
     cluster_size="190"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['035bca826eff1349a0b7c15a2f09fa69','03e14c6f5248e41bb6e1e920d3138a4c','160a106b51cf5c90b2384a367a7da7c1']"

   strings:
      $hex_string = { 7954687265616400066578697374730007666f724e616d650003676574000f6765744162736f6c7574655061746800126765744170706c69636174696f6e496e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
