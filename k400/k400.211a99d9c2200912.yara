
rule k400_211a99d9c2200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k400.211a99d9c2200912"
     cluster="k400.211a99d9c2200912"
     cluster_size="122"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tdss zusy autorun"
     md5_hashes="['006d51a2191064e3c9ea1cabf4f0d30d','05a56be04a250722d4b8240d035f6f74','4d71db99da0743d2e80d56691e4cdf8a']"

   strings:
      $hex_string = { 6f66742d636f6d3a61736d2e763122206d616e696665737456657273696f6e3d22312e30223e0d0a3c6d735f61736d76333a7472757374496e666f20786d6c6e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
