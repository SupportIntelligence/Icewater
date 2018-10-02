
rule m2319_35bb5cc1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.35bb5cc1c8000932"
     cluster="m2319.35bb5cc1c8000932"
     cluster_size="64"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['513223ffba6b59e86f224b83d4952162411fecb5','b2c0c3bc469ab955c294b47b042cb2416b98d5df','9daa4c7125888041274b890f0bdc33b709c8705d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.35bb5cc1c8000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
