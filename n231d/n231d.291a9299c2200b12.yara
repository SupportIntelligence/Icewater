
rule n231d_291a9299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.291a9299c2200b12"
     cluster="n231d.291a9299c2200b12"
     cluster_size="60"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos triada andr"
     md5_hashes="['a72402d9be882f303ac5ab04990cfda37410871a','8c991428cc34cc517735780df694b2065957d81f','f27ed92cf229f0242bb8e27b4f7b9c689c214722']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.291a9299c2200b12"

   strings:
      $hex_string = { 4f84832ed62123cd061b1304e3eab874d0dacb4eef5bdc1831161468369c53a45494990786f888438df9ba4957b0feb7fd7175c9bfe028df3f2d794002dd2bce }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
