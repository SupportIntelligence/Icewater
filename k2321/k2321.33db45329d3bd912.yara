
rule k2321_33db45329d3bd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.33db45329d3bd912"
     cluster="k2321.33db45329d3bd912"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['007b16d06348b9d8959e1d8e2902cb0f','0b1ecd5033a021665a19bf16e48c5997','fe8841ca0fc3b08e373816966325efe2']"

   strings:
      $hex_string = { 6ef2b01037a05505a4958c2dfd77e259ea198dcc2473877407bacf6a0809096b1f71bc5703d112e6b305d3817cf06d753900c9acdd8e33e9976fb985aa8a4664 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
