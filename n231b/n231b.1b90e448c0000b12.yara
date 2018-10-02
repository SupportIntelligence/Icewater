
rule n231b_1b90e448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231b.1b90e448c0000b12"
     cluster="n231b.1b90e448c0000b12"
     cluster_size="30"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos faceliker script"
     md5_hashes="['bfc913a77860bc7606b7e6e7388122e44293e5da','c195382ea2d6c7d6603ee107af9c6507919bc237','d5db21437fcb86482d3e991baefd8e8ed640795f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231b.1b90e448c0000b12"

   strings:
      $hex_string = { 2f76372f4371384b79716843582d66314a3942734f79715f467659363332336d48555a464a4d6754767861473269452e776f6666322920666f726d6174282777 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
