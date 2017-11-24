
rule p2321_4b9c9cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p2321.4b9c9cc1cc000b12"
     cluster="p2321.4b9c9cc1cc000b12"
     cluster_size="6"
     filetype = "Zip archive data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="smsreg androidos riskware"
     md5_hashes="['35fd8e10f1f4ef2d2e3801593f329934','4a307ed1173f08f122131ba8a7ca00b8','fdd6434ea038f5d009128b4ccb7ff548']"

   strings:
      $hex_string = { f5aef759e2be03175714436ff44c4d4f7b29df2225a5a45c44ab457e70efd061a26ae52f38fbe9ce824aec639e1879cf0b050f49e3d69112c31e66d2cb6ce15f }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
