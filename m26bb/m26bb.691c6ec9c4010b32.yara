
rule m26bb_691c6ec9c4010b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.691c6ec9c4010b32"
     cluster="m26bb.691c6ec9c4010b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious moderate"
     md5_hashes="['4c19d6115bb4c5b9d050da8cf1471bc4854d8b60','b44ddbe8d0605b8928485fd6acba210434102250','ec5a76129def1e765ed050d99caea198845daeb2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.691c6ec9c4010b32"

   strings:
      $hex_string = { 004e0c0000ff01db000000080800737562756761676100ff15005348446f63567743746c2e57656242726f777365720003cc15590174047f080f07002d4c420d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
