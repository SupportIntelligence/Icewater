
rule k2319_291594b9caa00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.291594b9caa00b32"
     cluster="k2319.291594b9caa00b32"
     cluster_size="60"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['d904a39288a0c5cc2a3d8d928df7236c3fc0f756','2e9ccbd2a0a98c77e5cd78e77b4218d6b2c75b6d','08033a84c7b3a0fa18c7202d86f34c55346f463d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.291594b9caa00b32"

   strings:
      $hex_string = { 313139293a28332e2c32372e292929627265616b7d3b7661722052347639353d7b27413735273a66756e6374696f6e28582c4c297b72657475726e2058213d4c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
