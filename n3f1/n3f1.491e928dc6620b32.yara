
rule n3f1_491e928dc6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.491e928dc6620b32"
     cluster="n3f1.491e928dc6620b32"
     cluster_size="13"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="obfus androidos andr"
     md5_hashes="['04848568d3de9a70d8f32031935030d7','0877518cd2b9413b3cb01326a870cacc','e79a57493f333cbb71eec74fb83218ff']"

   strings:
      $hex_string = { 0b008acfbff71d404fb8bb5db14b1e42e25e6c73aad1b02b19b7c1c38811634aa80c6e3acb5b23c560511a691855c8188dfdc9e657c0943c9b39e07c3ee3b49c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
