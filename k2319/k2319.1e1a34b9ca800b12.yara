
rule k2319_1e1a34b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e1a34b9ca800b12"
     cluster="k2319.1e1a34b9ca800b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['adb4ffcc1794bf911bd23b3391b9030eb44aebac','e7ea2fdc0d54719562060cb101ccd549a34ab781','1f4e79d0a4e624bcc9bb97fd7e5f8e4f25468b7d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e1a34b9ca800b12"

   strings:
      $hex_string = { 72222c2758334a273a2866756e6374696f6e28297b76617220433d66756e6374696f6e286b2c53297b76617220453d53262828307842332c34322e364531293e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
