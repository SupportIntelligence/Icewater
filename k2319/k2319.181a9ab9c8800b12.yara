
rule k2319_181a9ab9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181a9ab9c8800b12"
     cluster="k2319.181a9ab9c8800b12"
     cluster_size="35"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem multiplug"
     md5_hashes="['88bc25c5f3a4fd313dfc9fb8f4ad4377cebc86bb','9e1f8ffe8a703dbe4aaac7ef55a93bc39b6386a2','97b75ef0ba6fc91f1db2c694dd69e5a15bdc7f8d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181a9ab9c8800b12"

   strings:
      $hex_string = { 646f773b666f7228766172207a346120696e205832673461297b6966287a34612e6c656e6774683d3d3d2828392e313945322c3078313336293c30783141423f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
