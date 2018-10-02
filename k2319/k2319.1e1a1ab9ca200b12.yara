
rule k2319_1e1a1ab9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e1a1ab9ca200b12"
     cluster="k2319.1e1a1ab9ca200b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a9bb95454e70f79e373550bdf5a2bcc6e77f0ba2','24b1dc0f18d60a6368703dd774f389b7234d5416','7016a94c8dcf0e9717c51102fd93ea7244c31f5f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e1a1ab9ca200b12"

   strings:
      $hex_string = { 72222c2758334a273a2866756e6374696f6e28297b76617220433d66756e6374696f6e286b2c53297b76617220453d53262828307842332c34322e364531293e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
