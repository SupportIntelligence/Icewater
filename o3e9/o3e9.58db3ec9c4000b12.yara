
rule o3e9_58db3ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.58db3ec9c4000b12"
     cluster="o3e9.58db3ec9c4000b12"
     cluster_size="572"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock tdss nabucur"
     md5_hashes="['0029d36fcbe47468402ee96c37f0f033','0136905c2e359c8398a90a0a7d3838d2','1bd2006462d11fb4c59b5d77dd8a5d4c']"

   strings:
      $hex_string = { 010001002020000002002000a8100000010050414444494e47585850414444494e4750414444494e47585850414444494e4750414444494e4758585041444449 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
