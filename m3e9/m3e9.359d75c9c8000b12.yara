import "hash"

rule m3e9_359d75c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.359d75c9c8000b12"
     cluster="m3e9.359d75c9c8000b12"
     cluster_size="906 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="pcclient backdoor cossta"
     md5_hashes="['a31fa8b268b9092170be89454ad5972d', '774ffacc56915dfa283722f780897bc5', '7b44ec767b4fb333fa305c81fd7aace0']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(94208,1024) == "a7c57260e2c43abbd700069feef5cce0"
}

