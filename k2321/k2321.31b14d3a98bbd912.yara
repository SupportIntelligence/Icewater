
rule k2321_31b14d3a98bbd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.31b14d3a98bbd912"
     cluster="k2321.31b14d3a98bbd912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['09daac1f2123dca5b72cb5de64733238','28d9dae5cbe988a8706e2c67c67e2ca1','964de83c9b79a116a0ffa306e50756b9']"

   strings:
      $hex_string = { bdb0df0b4e0293f3bc26e4631f862d4368d7cdb99dd4dcce1c5e45037724f01b0cb84d94448792e80972fb7d9b72eaff7a8533d1ab07f8214f0d1e2338ad497e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
