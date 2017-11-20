
rule k2321_0969592399eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0969592399eb1912"
     cluster="k2321.0969592399eb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['129b6acd43a85718fc4052ade2fb8d4d','4ceff5a2fd12dd8144468a2f29afbae8','cb93e1f0e8742c0729a23519df456a20']"

   strings:
      $hex_string = { 59e4f614c3db2d32de4a5ae9337fae52efba83402be307a6dd976ff8a63c8fb0127e869a236bb7d3a49de5d6acbfa7f2c0575edc3be7d20682ed08870e8ec1b4 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
