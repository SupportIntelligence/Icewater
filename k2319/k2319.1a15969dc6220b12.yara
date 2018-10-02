
rule k2319_1a15969dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a15969dc6220b12"
     cluster="k2319.1a15969dc6220b12"
     cluster_size="36"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['9c490c8e7338c397f5b5e16240f0ca4bd0d37dd8','29e13009bc00b35ddb3acafc3ad995f5ffd4ca99','6c76a8c1b42ac36ce04c2ca1d001858ad86a46c7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a15969dc6220b12"

   strings:
      $hex_string = { 6e646566696e6564297b72657475726e20545b565d3b7d76617220413d282831332e3545322c34332e34304531293c3d352e303745323f2833372c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
