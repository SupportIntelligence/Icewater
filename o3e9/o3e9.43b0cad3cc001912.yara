
rule o3e9_43b0cad3cc001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0cad3cc001912"
     cluster="o3e9.43b0cad3cc001912"
     cluster_size="780"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['036deb0e4f5a5e509d9fa96e908a7e48','03dc52a4507509bfd8afa5640f28dc36','163d75a95bc5a813944e9600422d9296']"

   strings:
      $hex_string = { 4833c9a3fcca4c0038080f94c141518d4de4e899deffffe9120100005357b988b44a006a128bf98bf05b8a1684d274093a17750546474b75f10fb6160fb6372b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
