
rule m2321_331a464cdabb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.331a464cdabb0912"
     cluster="m2321.331a464cdabb0912"
     cluster_size="199"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup lethic zbot"
     md5_hashes="['03e12b6cc7ef5089940bf0c4e8fe3ca5','0601ffb0949032866341ee178bdf8669','16ba1c1281fb6dd3479f24f6e1725264']"

   strings:
      $hex_string = { dfc34f2a5c8d13760b7175381f85bce5c11b3f21acfed38bb688ead1161d3d89b57833458150a152f42cb12b3bef47700a42effb06205114a8d4c7635fe2546e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
