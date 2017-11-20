
rule m3e9_331a464cdbbb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.331a464cdbbb0912"
     cluster="m3e9.331a464cdbbb0912"
     cluster_size="41"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup zbot lethic"
     md5_hashes="['01feec736d37bd22b601365d94e9a86e','02fd20fa47f6dae5e3c78f71c4ae6c25','6b1cc65897dd041f786c45d2f907fb62']"

   strings:
      $hex_string = { dfc34f2a5c8d13760b7175381f85bce5c11b3f21acfed38bb688ead1161d3d89b57833458150a152f42cb12b3bef47700a42effb06205114a8d4c7635fe2546e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
