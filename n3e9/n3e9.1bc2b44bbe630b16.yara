
rule n3e9_1bc2b44bbe630b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc2b44bbe630b16"
     cluster="n3e9.1bc2b44bbe630b16"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious bkkvi"
     md5_hashes="['072071a80f7a74239c13a6be43d8e8cb','1db742180499777a9b98ddf2f87bc182','fcd988ac2202d214ef7d25ef930f4971']"

   strings:
      $hex_string = { 006e000e0053007400610063006b0020006f0076006500720066006c006f0077000d0043006f006e00740072006f006c002d0043002000680069007400160050 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
