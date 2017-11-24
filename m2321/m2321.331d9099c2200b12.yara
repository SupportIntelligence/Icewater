
rule m2321_331d9099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.331d9099c2200b12"
     cluster="m2321.331d9099c2200b12"
     cluster_size="11"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['508761e0a4194c9bfeb67f2d5ed367ea','5326761ee26096c987d2a7aea9962330','f8dff87e8a4bd1aa5aa0791985ef4387']"

   strings:
      $hex_string = { 9827d4c6a8a2492ddfe1ad792207fe7e467fdad09f1fe84f2b8767688f4ee563593324e77ac8052aac3093d70a54f32cff43adab3c85b884322e6af9cea1aa03 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
