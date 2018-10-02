
rule k26bb_528ae8e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.528ae8e9c8000b32"
     cluster="k26bb.528ae8e9c8000b32"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious virut attribute"
     md5_hashes="['81b30c4f231511f2b14ca32f19106314e4ca3ab8','172452d50e4991938a2fe334694f0ee3b7d11dbf','5f86507f473667c9b7ba3d072fb4118a78ec7940']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.528ae8e9c8000b32"

   strings:
      $hex_string = { 84600001f7d68935886000015e5f5bc9c3be4fe640bbebe690909090908bff558bec568b750833c03b750c731185c0750d8b0e85c97402ffd183c604ebea5e5d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
