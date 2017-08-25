import "hash"

rule o3f0_519b5ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.519b5ec1c8000b12"
     cluster="o3f0.519b5ec1c8000b12"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="malicious fner icloader"
     md5_hashes="['743369c57ea5591f3886c0647e40a34e', 'c7f590931c571e3c506afafa7bcbc90d', '5d32197d1db38a77b8b160c18e21ac18']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1249280,1024) == "422c688d1b93d8df3935d4e78be67fb2"
}

