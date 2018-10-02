
rule j3f8_5066e6b1b93b0130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5066e6b1b93b0130"
     cluster="j3f8.5066e6b1b93b0130"
     cluster_size="62"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun androidos origin"
     md5_hashes="['e52be0cc31880c21bb452187c06a4c949ed75e67','fde19d69d50acc09198d4762eadb14f566c4a2ad','51de28d360fda3b92a75baef3059f501f8d9d699']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5066e6b1b93b0130"

   strings:
      $hex_string = { 6c76696b2f73797374656d2f446578436c6173734c6f616465723b001e4c6a6176612f696f2f42756666657265644f757470757453747265616d3b000e4c6a61 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
