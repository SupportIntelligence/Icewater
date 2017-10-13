import "hash"

rule j3e9_55ab16c3c8000132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.55ab16c3c8000132"
     cluster="j3e9.55ab16c3c8000132"
     cluster_size="56 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="crytex hublo geksone"
     md5_hashes="['aae961ab644771c86f558f8e725c45ac', 'af4a2a1cbfd46ffb46bf1c05d7cce035', 'a8da8d70bffd52257dd6e5940065c0b2']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "d7825b38be6ce41176c97e368c55c399"
}

