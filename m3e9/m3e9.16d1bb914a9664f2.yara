import "hash"

rule m3e9_16d1bb914a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d1bb914a9664f2"
     cluster="m3e9.16d1bb914a9664f2"
     cluster_size="266 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="shipup razy zbot"
     md5_hashes="['a30acf74a81021cf553b50635c303888', 'c3f2fe57fda18845126aad95bc1efbab', 'bdc05d0d268068a7eb9c39a35549a1bb']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(2048,1024) == "9967db6677f0ed6b8e78591467bc9e49"
}

