
rule j26bf_091ee688c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.091ee688c0000b32"
     cluster="j26bf.091ee688c0000b32"
     cluster_size="126"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="starter zusy malicious"
     md5_hashes="['de319375bc7cd4029f903cb6c2e925f805687387','b02ab729928df7dd53757152c1b15eaac52cf2a6','2b55e6bc90dabd69ff164c0def3db8183f7f980d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.091ee688c0000b32"

   strings:
      $hex_string = { 734f626a65637450726f7669646572004170706c69636174696f6e00576562536572766963657300457175616c73006f0047657448617368436f646500547970 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
