import "hash"

rule m3e7_1a707a1f46620b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.1a707a1f46620b14"
     cluster="m3e7.1a707a1f46620b14"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="shodi virut prepender"
     md5_hashes="['866fd92a049ef5326ec925f9e685a636', 'd34caf927db1c898d90b1037065b5ef1', '866fd92a049ef5326ec925f9e685a636']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(12288,1024) == "8e58efdccc5d126553629034a59cc997"
}

