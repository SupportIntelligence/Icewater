
rule n3e9_1b625cc3c8001112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b625cc3c8001112"
     cluster="n3e9.1b625cc3c8001112"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa vilsel chydo"
     md5_hashes="['1e05f9b1cf8ae6efbb986c57eadf78f8','3016122d591ca7dbcfbf112f33e02c90','f99bd71714c44b744f5861e0f16b3966']"

   strings:
      $hex_string = { 44f8b4769bd9c7f48961ef04868e292a92a84a233d8a955bea7d526051911a4d561d555d2ddaca961b9332cff5aaf1aca36670c1e6fbb8c90be82f9e6d3420fe }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
