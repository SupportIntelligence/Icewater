
rule n26bf_129b05cdc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.129b05cdc6220b32"
     cluster="n26bf.129b05cdc6220b32"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickd banload kryptik"
     md5_hashes="['6e8b133440acd9db77c5393c1a9a38e0b2b6e967','1a7fd795684a55f3139661681e9b8fdeea780cc7','3055cf2daddaec4ecac16d85cfa8a443ce6eae28']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.129b05cdc6220b32"

   strings:
      $hex_string = { 6ca0ff00c7f4fb3bc39e82ead87e97dab1cb6201283876f92a290305eb177cd9866d228e5547e14be5e8bc1a58ab706bf2cc4591dbe3c6f89f59525f8ac08b2d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
