
rule n26bb_51b69892dda30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.51b69892dda30b32"
     cluster="n26bb.51b69892dda30b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack ayndlhai patched"
     md5_hashes="['91fd33341b36e725866e95092faff9e1851f8caf','a87416363082cc8f2e46263450e178e2ac19f459','e93765aed18e4f3c7e79edf7baf7ee9fdff3e734']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.51b69892dda30b32"

   strings:
      $hex_string = { 25747a83a48694b9f5e753bdc6ff81f8df4d4808cc6d11dc59125722fc52c23d9ea15842bfe2f00fc88ed254d1c4c70a1b51e11385af78cca86a3cf6c3045db4 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
