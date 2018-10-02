
rule m2319_3ad297c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3ad297c9c4000b12"
     cluster="m2319.3ad297c9c4000b12"
     cluster_size="160"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['e45ebaf3c116a21fc9fbdd7b39bf67b588e9eb8e','30d0dcae13c274c818e20b50c8fdf5e5dda7b9b1','e626f14de9c3ca3cb126fcd570a9f224e4af4909']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3ad297c9c4000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
