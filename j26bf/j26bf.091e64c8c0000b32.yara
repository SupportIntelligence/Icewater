
rule j26bf_091e64c8c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.091e64c8c0000b32"
     cluster="j26bf.091e64c8c0000b32"
     cluster_size="98"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy starter malicious"
     md5_hashes="['a28a4a3eeb668e25fae9470cc864ead1a3816b1c','51e8bb2896a93f6aadea467e9ba6126bf1848105','0dd9af151d4862bd4f283029b0bb65cd04edc2d7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.091e64c8c0000b32"

   strings:
      $hex_string = { 734f626a65637450726f7669646572004170706c69636174696f6e00576562536572766963657300457175616c73006f0047657448617368436f646500547970 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
