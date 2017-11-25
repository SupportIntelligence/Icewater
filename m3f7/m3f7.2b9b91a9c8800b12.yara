
rule m3f7_2b9b91a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2b9b91a9c8800b12"
     cluster="m3f7.2b9b91a9c8800b12"
     cluster_size="51"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker html"
     md5_hashes="['04c1d8c39e0665f3780263551e01111f','05d26d83d80a52064ded7f57236325a1','67a55d8154fe40fdf3509712d2cfc974']"

   strings:
      $hex_string = { 617928293b0a696d67725b305d203d2022687474703a2f2f322e62702e626c6f6773706f742e636f6d2f2d7569745837524f507454552f5479762d47344e415f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
