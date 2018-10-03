
rule j2319_039b6d0e9ee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.039b6d0e9ee30932"
     cluster="j2319.039b6d0e9ee30932"
     cluster_size="159"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="megasearch diplugem multiplug"
     md5_hashes="['78c5cf9b0c3185dcf6f079eafb70f9ac1a8a6931','478aa9a05cf708d43308ae6e5f60bf27808f1e29','42477ea08d4977aa125c3623c9619d31e01a17ec']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.039b6d0e9ee30932"

   strings:
      $hex_string = { 2e67657454696d6528292f314533297d7d63617463682863297b72657475726e20307d7d7d2c6462636c6173733d7b656e67696e65733a5b227072666462222c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
