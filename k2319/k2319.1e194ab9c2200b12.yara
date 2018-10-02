
rule k2319_1e194ab9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e194ab9c2200b12"
     cluster="k2319.1e194ab9c2200b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['3e00549cb864b1c8a365506b92176974f7210ac9','ef8fcf6249e2d209c43d80165e33810012bbfe5b','eba3746bae11d48b3cd3d78fa5b1f55563b64592']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e194ab9c2200b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20465b585d3b7d766172206e3d28342e333245323e28307837302c313039293f2830783139362c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
