
rule k2319_1e1a1ab9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e1a1ab9caa00b12"
     cluster="k2319.1e1a1ab9caa00b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['29571cfecd36045f9bcd2e91938bc99988ac0365','3a0abd661c11d1f96e01b036c1940c38a543845d','468df27e3a1f6ea33a37bef04ecf05b99b50c4db']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e1a1ab9caa00b12"

   strings:
      $hex_string = { 72222c2758334a273a2866756e6374696f6e28297b76617220433d66756e6374696f6e286b2c53297b76617220453d53262828307842332c34322e364531293e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
