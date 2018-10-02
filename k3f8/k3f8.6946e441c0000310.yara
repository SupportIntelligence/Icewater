
rule k3f8_6946e441c0000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.6946e441c0000310"
     cluster="k3f8.6946e441c0000310"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos jisut ransom"
     md5_hashes="['f00dc64f659e10920b0e97115a6dc04c13985ceb','b59ce99f0776c5b3f1c0e8c54b931650f2a89004','567b86ff9368bb49d2ac7bb9fbd9516166d6b45e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.6946e441c0000310"

   strings:
      $hex_string = { 6a6176612f6c616e672f537472696e674275666665723b0001560002564a0002564c0003564c490003564c4c0002565a000e57494e444f575f53455256494345 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
