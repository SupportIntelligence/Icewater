
rule k2319_6910ea59d9bb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6910ea59d9bb0932"
     cluster="k2319.6910ea59d9bb0932"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script browser"
     md5_hashes="['5db56d6da53b6002d75e9a96740e136b3a74244e','53e8aae636e53f227bdec3ed5fe2a377c2d92650','d2d65bba5984ed88312d57953bd762a023546014']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6910ea59d9bb0932"

   strings:
      $hex_string = { 5b585d213d3d756e646566696e6564297b72657475726e205a5b585d3b7d766172204f3d282830783132392c36382e293c3d28307836412c322e31394532293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
