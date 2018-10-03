
rule j26bf_091ee6c8c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.091ee6c8c0000b32"
     cluster="j26bf.091ee6c8c0000b32"
     cluster_size="85"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="starter malicious atros"
     md5_hashes="['e00bff002108f0df95595179df280d3ab326f94c','1e497ddf8ad5921490e372c464ff63c3d81e9d26','887e9e94d3f0c48f65054151ab3f9b4786b0ed87']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.091ee6c8c0000b32"

   strings:
      $hex_string = { 734f626a65637450726f7669646572004170706c69636174696f6e00576562536572766963657300457175616c73006f0047657448617368436f646500547970 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
