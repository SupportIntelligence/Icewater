
rule k2319_1a129ea9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a129ea9c8800b12"
     cluster="k2319.1a129ea9c8800b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b66f0b791e5fc2dfd5e7e1acce252a098a5d4b62','c9c801f311e4765df2e5b1cb4f68682348ed6024','1dcbfd6021940a4f0029ee39f0fbb148c30ef91b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a129ea9c8800b12"

   strings:
      $hex_string = { 30783234312c3235292929627265616b7d3b666f72287661722064397420696e205432413974297b6966286439742e6c656e6774683d3d3d283131322e383045 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
