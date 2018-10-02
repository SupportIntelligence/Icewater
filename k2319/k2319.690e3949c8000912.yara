
rule k2319_690e3949c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.690e3949c8000912"
     cluster="k2319.690e3949c8000912"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script browext"
     md5_hashes="['ca6714a7599583fdc520515afff75798375a9608','73a4b5a683a13db634a142dd633b81578da05801','5cedc419fcf608c3f7fe31a900119baae0f23f21']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.690e3949c8000912"

   strings:
      $hex_string = { 44333d66756e6374696f6e2862297b76617220423d27223b7d273b76617220643d273d22273b76617220653d2835302e3c3d28307842382c332e36354532293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
