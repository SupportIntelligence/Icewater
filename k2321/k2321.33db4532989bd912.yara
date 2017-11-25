
rule k2321_33db4532989bd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.33db4532989bd912"
     cluster="k2321.33db4532989bd912"
     cluster_size="26"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['01e73ea36fb0e1e418bf6708f901b3c5','103cbc763f782bd16a41d0d04c75e1fc','b80148fd2a065558dbe1929829b2135e']"

   strings:
      $hex_string = { 6ef2b01037a05505a4958c2dfd77e259ea198dcc2473877407bacf6a0809096b1f71bc5703d112e6b305d3817cf06d753900c9acdd8e33e9976fb985aa8a4664 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
