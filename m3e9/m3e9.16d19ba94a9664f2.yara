import "hash"

rule m3e9_16d19ba94a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d19ba94a9664f2"
     cluster="m3e9.16d19ba94a9664f2"
     cluster_size="642 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="shipup razy zbot"
     md5_hashes="['3a1782d2d37d2bf295767850fc6843a4', '73f426346d1b30d665e0d0c2e35bda20', '02f122fb24cd743eeaf6862a37c29c62']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(2048,1024) == "9967db6677f0ed6b8e78591467bc9e49"
}

