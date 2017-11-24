
rule m3e9_436c4a14a8696b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.436c4a14a8696b96"
     cluster="m3e9.436c4a14a8696b96"
     cluster_size="120"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis adload clickdownload"
     md5_hashes="['025b8668c4d2406998e0de9febf4c9e1','05242c239ecaf83875688369e1c5e885','223a9af2bc6eeab2d99fd655b0ef7eac']"

   strings:
      $hex_string = { b008481e47a950ab5d4d2cda32bf58fe850c6c9acc43d859fb9b01f64f2b309233ddde9fc06906709c68ce638e0a5bf7c49e9da862df132f003aa17e0222ad7c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
