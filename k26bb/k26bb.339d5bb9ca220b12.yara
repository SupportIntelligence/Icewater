
rule k26bb_339d5bb9ca220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.339d5bb9ca220b12"
     cluster="k26bb.339d5bb9ca220b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious virut attribute"
     md5_hashes="['21344edc6fddc241aeb091c60d8fb2ed91b48db4','2cd212c39f92ddc8a5546d049b991a209cd7c0b6','4ed39a9180cca1d48285ea720f44f724bf94fcf8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.339d5bb9ca220b12"

   strings:
      $hex_string = { b5e5328a42988719f712b907bfc01c67eb857efb44a9e8aedb702cec54af5f57d9f075394db3ba7fa40c9e3f62994b9cb082a8634fbb41ac4c5df802c53091b7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
