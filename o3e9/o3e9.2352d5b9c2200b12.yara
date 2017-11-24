
rule o3e9_2352d5b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2352d5b9c2200b12"
     cluster="o3e9.2352d5b9c2200b12"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious adwaresig toolbar"
     md5_hashes="['40caae0e3c07dbdafbcf1625ada4a0d3','4890eab637a7425267e4e365f30a9204','c04ee7734a63ec9c8f23b53e48fe3499']"

   strings:
      $hex_string = { 117d07eb0ff339e5edb6ef587f99c56ddeb0ff00338adbbd61fe6715b77ac3fcce2b687b9314d6d7105c2fad6f750bc1710f2e3ca29519245e5fb3c95b2c84a5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
