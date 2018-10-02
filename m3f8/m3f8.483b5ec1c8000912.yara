
rule m3f8_483b5ec1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.483b5ec1c8000912"
     cluster="m3f8.483b5ec1c8000912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jisut lockscreen androidos"
     md5_hashes="['f9230d2e37ac0858ec1cddbbe2d621a68e120541','e6ab070e55ac7ac5aa739966e9c29721b0739986','9da0bbc1a6cfdd8a83fa38aecdf84433dc95196b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.483b5ec1c8000912"

   strings:
      $hex_string = { 00050200001a00d700080200001e002500a10200001f003000930200001f000401ad02000020000c008d020000200006009202000020006700ac02000022002c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
