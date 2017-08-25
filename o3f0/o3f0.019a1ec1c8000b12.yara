import "hash"

rule o3f0_019a1ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.019a1ec1c8000b12"
     cluster="o3f0.019a1ec1c8000b12"
     cluster_size="80 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="malicious attribute classic"
     md5_hashes="['e1f37659de75fe42f8e3100cec47f54e', '85d17818795b88a600b904f50cd0aef5', 'c7e39dc5af36d43e06c2eb99005baa4d']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1245184,1024) == "9855a4a929abdfd1c8aadda0d4e74fe1"
}

