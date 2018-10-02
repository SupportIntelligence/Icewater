
rule k2319_5a4a9ea9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a4a9ea9c8800b12"
     cluster="k2319.5a4a9ea9c8800b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem script"
     md5_hashes="['abecac48a2a4f76c5eab874eb3207e9058619975','beab688c2c5b795c7182e047506e68246f81dc0e','dedaa591d3dce5e5477af78dadc84a6149b16516']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a4a9ea9c8800b12"

   strings:
      $hex_string = { 6b7d3b666f7228766172206f396a20696e20743651396a297b6966286f396a2e6c656e6774683d3d3d28307834453e28307841372c3078313038293f3139323a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
