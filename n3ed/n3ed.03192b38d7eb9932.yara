import "hash"

rule n3ed_03192b38d7eb9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.03192b38d7eb9932"
     cluster="n3ed.03192b38d7eb9932"
     cluster_size="4440 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="elex xadupi riskware"
     md5_hashes="['029d7ffec0d619a64d1795bda555e257', '0ba5bb11519bd30c83062df7809b7be6', '08312b65dbd20dc39608530c8e848024']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(739328,1536) == "1baacf8752122169d720c6e2cd09c896"
}

