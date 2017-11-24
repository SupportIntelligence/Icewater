
rule m3e9_10d2c6d1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.10d2c6d1c4000912"
     cluster="m3e9.10d2c6d1c4000912"
     cluster_size="23"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys pronny"
     md5_hashes="['10193c60af1149fc8973463f821c99c0','445243b0d1f0b3fe40f330cf0220a3c2','d8579e17e13a02a1110cfefb2cbc949c']"

   strings:
      $hex_string = { 314d4e4e4f5b676969676763687277949eb0b0b1bdbddaccccf2f298000000d9ffff0203070808070a0f101316181b4932494a4a4b4c51625f51403d50616f71 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
