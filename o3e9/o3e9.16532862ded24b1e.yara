
rule o3e9_16532862ded24b1e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.16532862ded24b1e"
     cluster="o3e9.16532862ded24b1e"
     cluster_size="22"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr dlboost"
     md5_hashes="['03346cc67fa4d53da70072752d6b368d','0ad43d9d36785282ccf246e979f72b49','ae435cd62f9950a34c20200e0b97ca46']"

   strings:
      $hex_string = { 6c01e21d7189394473838f21eb94e6d7bfdd14d47ae033c8568b1807931cabe8593bcafbd0f3c5fdf5350e5eb5aadbbecc74f1d105ff2896cb1fd212856a7654 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
