
rule k2321_2b140a56d9bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b140a56d9bb0912"
     cluster="k2321.2b140a56d9bb0912"
     cluster_size="27"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ganelp autorun emailworm"
     md5_hashes="['10dcc02d870b09ac9820ddb1e12691d0','25188058f222fdbe37eaaf1021c0e793','b1abee3d800e07eaa09c42b8beb00734']"

   strings:
      $hex_string = { aded6dc5bc03dd5e105ac9947957f722a9b3e175983cdc567b07cb200695088260b6b50ca2c99e26183383a75bbba19a86d8e549372d2c4dc09324765d5c0413 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
