
rule m3e9_231422c5aa211916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.231422c5aa211916"
     cluster="m3e9.231422c5aa211916"
     cluster_size="96"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut patched virux"
     md5_hashes="['04ad2a8b58b859fe7f54f0a388bab410','06b2d24883a5ce710911d534d2ab418e','31df662bf328e95a62f9f2997917324f']"

   strings:
      $hex_string = { dc3f6417fae8162580ce8a0191fb2f491ea4df850a2d3e9442605acd2c038f23d4dd3b11d5fdbbc6d38d9893ff2fe77704c70d5327400c4c294af24b653d4189 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
