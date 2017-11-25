
rule o3e9_594e4a6adceb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594e4a6adceb0932"
     cluster="o3e9.594e4a6adceb0932"
     cluster_size="142"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['0101dfa5c4e567201da0a17a630f43ba','01056ec7cac5b8e20c9e4b4a710e6bd6','176f94079071395a0b5c815a552784f4']"

   strings:
      $hex_string = { 2800250064002900110049006e00760061006c0069006400200063006f0064006500200070006100670065000800460065006200720075006100720079000500 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
