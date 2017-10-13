import "hash"

rule m3e9_31b9e849c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31b9e849c0000932"
     cluster="m3e9.31b9e849c0000932"
     cluster_size="1858 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="swrort elzob zusy"
     md5_hashes="['0815a08e17ecaec707cff3368276b753', '184369eebe3df55cd71780981e95e4bc', '1b0e3d2b5224c1bafa60fc37d97cd435']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62464,1024) == "1db9d97aa3077042ff06074d16a50ac7"
}

