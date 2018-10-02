
rule m26bb_178f17a14a000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.178f17a14a000b12"
     cluster="m26bb.178f17a14a000b12"
     cluster_size="62"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut malicious crypt"
     md5_hashes="['1629f079931795b29b82cca2cc2ab0844ad54ef8','a4f79331508b635e7eba604c5cf74d3bbc241eda','a1144e1cca66bbd2f2e15166d9c8671d4c57ac98']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.178f17a14a000b12"

   strings:
      $hex_string = { 0101012a9589414948242b2312151b300101013a947a3e5d4e3f4035110e14380101013b91584c5c5b46474517131f2e010101438f55546c5a4d534b1d1e282e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
