
rule o3e9_43b0cad3c4001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0cad3c4001912"
     cluster="o3e9.43b0cad3c4001912"
     cluster_size="183"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['022efb2b3cdd015423f462467be9c848','03137cd6e11d4e2dd899e29b85fe6d87','2fa9407ab17c95c11777b9d987c85bad']"

   strings:
      $hex_string = { 4833c9a3fcca4c0038080f94c141518d4de4e899deffffe9120100005357b988b44a006a128bf98bf05b8a1684d274093a17750546474b75f10fb6160fb6372b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
