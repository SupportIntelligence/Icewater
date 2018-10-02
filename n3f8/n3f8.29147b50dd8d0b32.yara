
rule n3f8_29147b50dd8d0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.29147b50dd8d0b32"
     cluster="n3f8.29147b50dd8d0b32"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos boogr smforw"
     md5_hashes="['cf6aebd36d1fc9934e2ae1e3dff0d9a19dbc8088','a0731ec03b68cc4e5291bd540c5e960b6bb53b92','4c7703e9418225e431eba90d093e86dd8dd9dfe7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.29147b50dd8d0b32"

   strings:
      $hex_string = { 636c756465642060606c696e6573272720656c656d656e7420776974682074797065200012424f44595354525543545552452e6a6176610005424f44595b0003 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
