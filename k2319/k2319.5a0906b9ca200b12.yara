
rule k2319_5a0906b9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a0906b9ca200b12"
     cluster="k2319.5a0906b9ca200b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a1450b9f41724f2d8e93dff36f9940e912e0a026','725bac92b58d62de07d91bf30c34ccb254daa31b','1b54a119d2fa3284bd83df3054678f644726be78']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a0906b9ca200b12"

   strings:
      $hex_string = { 3f283132352e2c313139293a28307832452c3930292929627265616b7d3b7661722043334b326e3d7b27613871273a362c2758334a273a226f64222c276b3671 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
