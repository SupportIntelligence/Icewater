import "hash"

rule m3e9_31b9e849c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31b9e849c0000912"
     cluster="m3e9.31b9e849c0000912"
     cluster_size="536 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="swrort elzob zusy"
     md5_hashes="['659268cf32f41d0eb5a8d272f73043e6', '4c1bfb012778adf2bec7f701e9db6085', '1c7d58e6d33d8198ca0058761018fa94']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62464,1024) == "1db9d97aa3077042ff06074d16a50ac7"
}

