
rule k2319_5a0906b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a0906b9ca800b12"
     cluster="k2319.5a0906b9ca800b12"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['d3154614d26f9d1a403d1a09d5fd6985bb7b3e55','2dd44db7d4a285941d73c90bc7182bd32dda3108','edf053cab652c70eb46ee52e8ed3f21ca1e0f544']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a0906b9ca800b12"

   strings:
      $hex_string = { 3f283132352e2c313139293a28307832452c3930292929627265616b7d3b7661722043334b326e3d7b27613871273a362c2758334a273a226f64222c276b3671 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
