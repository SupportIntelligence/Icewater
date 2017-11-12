
rule m3e9_13b36928d8bb9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b36928d8bb9912"
     cluster="m3e9.13b36928d8bb9912"
     cluster_size="473"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lethic zbot shipup"
     md5_hashes="['0341a6e35c19c75b6d4dd56772ea7206','039f172dc01b7546e4153de4cee79739','1db8bb2c6b52f8c8f7da5df84c993702']"

   strings:
      $hex_string = { f3dccc1bd70886a6755a636633aa635c767823f2d6fb03f23503abccc4e4b3ab8f3dc4977db31800006f759a635167742d5d759a74b5b7fb03f235c3aa8cc2a4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
