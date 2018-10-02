
rule k2319_381f16b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.381f16b9ca800b12"
     cluster="k2319.381f16b9ca800b12"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b244d370bb527882e126ccc3462791ee60757f7a','613a4942da8b661ac9b7642b7eb9780710af5bf7','9ad8cdd3f16bca40938afe940d2714aa5a35fc3c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.381f16b9ca800b12"

   strings:
      $hex_string = { 572c4e2c7a297b696628415b7a5d213d3d756e646566696e6564297b72657475726e20415b7a5d3b7d76617220533d2828307846392c33372e293e283132322e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
