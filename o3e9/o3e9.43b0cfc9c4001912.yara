
rule o3e9_43b0cfc9c4001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0cfc9c4001912"
     cluster="o3e9.43b0cfc9c4001912"
     cluster_size="119"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['0469552fb90679cd70db9e682a0f4245','0e113ea66fb1094a412e4223e2e483db','644ce9835e2910da380eceaeb9760da9']"

   strings:
      $hex_string = { 4833c9a3fcca4c0038080f94c141518d4de4e899deffffe9120100005357b988b44a006a128bf98bf05b8a1684d274093a17750546474b75f10fb6160fb6372b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
