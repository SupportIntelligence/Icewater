import "hash"

rule m3e9_16d1999b4a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d1999b4a9664f2"
     cluster="m3e9.16d1999b4a9664f2"
     cluster_size="303 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="shipup razy zbot"
     md5_hashes="['c5fe0841926ca5e33da730d91d55542f', '7d5137911503397fac17ea6928ad0c9e', 'dd973658cd7b08d4a40ba9eab9b15611']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(221184,256) == "be05042a99d973e40089853814e9dd5a"
}

