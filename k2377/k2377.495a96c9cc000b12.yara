
rule k2377_495a96c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.495a96c9cc000b12"
     cluster="k2377.495a96c9cc000b12"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['06323177aa11316adf2e130af71630c5','4566843ad3cc41dbfa00fd14d2a03b26','dd891f98ea10e924dbff171676dfda0f']"

   strings:
      $hex_string = { ace0ebc3d6f3ef967773e27f0ce7ddea909bc6da4c3120581d6081197924aac1d7f6b7226ab3b23215f3a03089481e55a9780e69e80aa20d84c928164aae1795 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
