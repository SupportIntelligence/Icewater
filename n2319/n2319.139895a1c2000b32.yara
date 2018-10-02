
rule n2319_139895a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.139895a1c2000b32"
     cluster="n2319.139895a1c2000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack faceliker clicker"
     md5_hashes="['5ebfdf9c06ef0ca31bf69f77d802f46f3ac710d0','11aa0d7ab78eda2b10fb285368899bd61169ea7b','184e510959327ebff12db42e259d598d45f7e5a1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.139895a1c2000b32"

   strings:
      $hex_string = { 68287361297c7c5b5d3b76617220623d7728292c633d66756e6374696f6e2861297b72657475726e20612e7265706c616365282f5c5c2f672c2225354322292e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
