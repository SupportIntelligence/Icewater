
rule k26bb_528ae869c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.528ae869c8000b32"
     cluster="k26bb.528ae869c8000b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virtob malicious virut"
     md5_hashes="['4763561f34f8fcaa4cc4449f839c66a65cd37038','fefae613c6018a9a20f64a1cf08dd5f7885009ad','143645edbda2e704edf6c26d02275ab728fb10ee']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.528ae869c8000b32"

   strings:
      $hex_string = { 84600001f7d68935886000015e5f5bc9c3be4fe640bbebe690909090908bff558bec568b750833c03b750c731185c0750d8b0e85c97402ffd183c604ebea5e5d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
