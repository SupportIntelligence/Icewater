
rule j3e9_131257d2c92bdb32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.131257d2c92bdb32"
     cluster="j3e9.131257d2c92bdb32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre bublik generickd"
     md5_hashes="['19e8e6ad45b3ea92becc7e8e06140849','20bc72bb1c81a8afa2a8cd7b35402f60','4619fa8791404a8fda97af15a4917455']"

   strings:
      $hex_string = { b348d79064f0570fa47e921f7f0b8f8851fcda8cc18b10d2c42fef0823fd46758ed134365f676afe6e0d3d2272f2d5594278964e33659c2e9b708fcfd59abff9 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
