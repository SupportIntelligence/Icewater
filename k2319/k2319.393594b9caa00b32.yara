
rule k2319_393594b9caa00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.393594b9caa00b32"
     cluster="k2319.393594b9caa00b32"
     cluster_size="88"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script adinject"
     md5_hashes="['249dd0c4fb32af76604edfc69e0dfa0da02e381e','f999f2fe43740c46270747694902fc2e28d6e2e9','7a7cb2d9c185f81cf0d93247a26bb22afd5b4ca7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.393594b9caa00b32"

   strings:
      $hex_string = { 2e2c3132392e292929627265616b7d3b7661722047326838673d7b27693948273a2256222c2762314d273a226e222c27443067273a66756e6374696f6e286439 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
