
rule o3e9_16532862ded26b1e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.16532862ded26b1e"
     cluster="o3e9.16532862ded26b1e"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster bundler installmonstr"
     md5_hashes="['08290b01c12ef1fb4b74bbcef3e593c2','0a6730ee2c2e9fa7f62e0b4b9d341e42','f518dd8e495d60b1be915950a07010c7']"

   strings:
      $hex_string = { 6c01e21d7189394473838f21eb94e6d7bfdd14d47ae033c8568b1807931cabe8593bcafbd0f3c5fdf5350e5eb5aadbbecc74f1d105ff2896cb1fd212856a7654 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
