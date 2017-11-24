
rule o3e9_68993ec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.68993ec9c4000b32"
     cluster="o3e9.68993ec9c4000b32"
     cluster_size="131"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock tdss nabucur"
     md5_hashes="['0045508412b3e7f7f2eb7d83aedefab1','03738b9d879fe5c96d0bbf7cb21e3ba0','4ea8e6537f7a3aef022b8725e291357f']"

   strings:
      $hex_string = { 010001002020000002002000a8100000010050414444494e47585850414444494e4750414444494e47585850414444494e4750414444494e4758585041444449 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
