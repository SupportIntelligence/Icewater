
rule n3e9_54da7b48c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.54da7b48c8000912"
     cluster="n3e9.54da7b48c8000912"
     cluster_size="26"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys jorik"
     md5_hashes="['1584783945173a103d8a05fd30c774c4','2afeb2fa2cced7319b7901ba8bf8cd9e','c04ab61ef49cd01d528c079d645151a1']"

   strings:
      $hex_string = { d2f1f2f2d5d3c4bcb7b79294998e0121b3d0f2d9f5f5f2c64243000000242d312d40b7d3d5f2f2f8d53a2c2830323c3d79beefd5d3d0bcb9b07da89594930214 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
