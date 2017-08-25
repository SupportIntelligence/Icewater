import "hash"

rule m3e9_16d1999b4a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16d1999b4a9664f2"
     cluster="m3e9.16d1999b4a9664f2"
     cluster_size="349 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="shipup razy zbot"
     md5_hashes="['6c2997fe21d26f21fb92da67197b3dd9', 'c79883387ef10622520ab1d16df99acc', '8799d045eead82c545b46dff44944219']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(235520,1024) == "e5c64c011f9df09a712f0d7b8c3391f6"
}

