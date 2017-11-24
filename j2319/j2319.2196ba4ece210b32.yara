
rule j2319_2196ba4ece210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.2196ba4ece210b32"
     cluster="j2319.2196ba4ece210b32"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery redirector html"
     md5_hashes="['0123cc19221deec64dfed363cd86f7a6','725b2c298626a8c41d812e9f8628e987','fbd4e9381476578ea652e88575e334aa']"

   strings:
      $hex_string = { 6c2f6a732f6a71756572792e6d696e2e706870272b273f272b2764656661756c745f6b6579776f72643d272b656e636f6465555249436f6d706f6e656e742828 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
