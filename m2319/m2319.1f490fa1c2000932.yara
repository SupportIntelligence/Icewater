
rule m2319_1f490fa1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1f490fa1c2000932"
     cluster="m2319.1f490fa1c2000932"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery html script"
     md5_hashes="['1f9d015cee05afc33cee770c5414ac4868df2519','533cbf612d44157ef5f9a8635d622ce049933d26','1a490902ffc70d9884f1719f2768e0ac51773a9a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1f490fa1c2000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
