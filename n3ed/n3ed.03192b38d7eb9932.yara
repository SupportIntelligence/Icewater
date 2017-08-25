import "hash"

rule n3ed_03192b38d7eb9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.03192b38d7eb9932"
     cluster="n3ed.03192b38d7eb9932"
     cluster_size="4395 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="elex xadupi riskware"
     md5_hashes="['0f37d169d8ab2365df981df657a96c81', '0088459e2b2cc83160c9c51709fcae65', '07b53e456e783ca5baec1a1ba4fe373c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(739328,1536) == "1baacf8752122169d720c6e2cd09c896"
}

