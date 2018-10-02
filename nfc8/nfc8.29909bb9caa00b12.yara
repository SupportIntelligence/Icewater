
rule nfc8_29909bb9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.29909bb9caa00b12"
     cluster="nfc8.29909bb9caa00b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker asacub"
     md5_hashes="['5f96a32c65b61e1dcde4de9f25f2cd9b1b303223','05ca09765deda628dbc95c9a2da12d7916d4e2c8','0432528ba2e1d90f5411150221b02dde4457cb3d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.29909bb9caa00b12"

   strings:
      $hex_string = { 7d4ba0ba7f40e723e88b5692948f58503a5d801c862bf31304fdbbc4460597640f257c29aaa9067288ccaff4b8f220a70a6dd1deeed948985e34c83119a8275f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
