import "hash"

rule k3e9_69694116ee211112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69694116ee211112"
     cluster="k3e9.69694116ee211112"
     cluster_size="537 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="upatre kryptik waski"
     md5_hashes="['a196804399d3507a12a31a295667a019', 'bc025ea51636cf2b6f4931f079b03340', 'c20b7d5cab4a37fcfa14c7f9beba6c20']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(30605,1047) == "3e668f8f512b80adc7f93df15521794e"
}

