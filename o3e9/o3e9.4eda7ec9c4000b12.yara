
rule o3e9_4eda7ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4eda7ec9c4000b12"
     cluster="o3e9.4eda7ec9c4000b12"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock tdss nabucur"
     md5_hashes="['b13b232d325fa4db41d00f9b57d3e675','b2dfcb0ce2672f5cefb3be6f4dc614b0','d9526103a8083c9338646e6731c99a08']"

   strings:
      $hex_string = { dce800b0c2d100566f83008595a300657d9900b5c8e200f2f8fc00b1c6ef00b6c9eb009fb4cc00d7e4f000b3c5d600475d66001d2823001d2721001a1e17000c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
