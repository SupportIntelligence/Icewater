
rule o3e9_153308e69ed249b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.153308e69ed249b2"
     cluster="o3e9.153308e69ed249b2"
     cluster_size="610"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster bundler installmonstr"
     md5_hashes="['00cd992eedf039fcaa3030542783a422','016ef76238cc9b82b864b30e06353641','08390442950bd4e5572c688cc068d567']"

   strings:
      $hex_string = { 6c01e21d7189394473838f21eb94e6d7bfdd14d47ae033c8568b1807931cabe8593bcafbd0f3c5fdf5350e5eb5aadbbecc74f1d105ff2896cb1fd212856a7654 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
