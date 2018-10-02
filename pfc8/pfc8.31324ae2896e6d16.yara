
rule pfc8_31324ae2896e6d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.31324ae2896e6d16"
     cluster="pfc8.31324ae2896e6d16"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp adlibrary adpop"
     md5_hashes="['9f91bf8d1b57798136e27608b3900220bb84eccc','1a36eb07a878f74e1b5f2dcc49b162570b7506e6','b4ae86f64c25bba342d95204c8304d62e20e1c10']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=pfc8.31324ae2896e6d16"

   strings:
      $hex_string = { 9621aa1d97415a761e9c4db1949d88804483e83129935cb5c50ac20943b3ccdf7aa07465d0e43201c959b42749fc2da8250e58e6c73d50c6ae1bfd18d68e1f37 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
