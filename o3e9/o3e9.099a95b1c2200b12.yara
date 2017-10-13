import "hash"

rule o3e9_099a95b1c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.099a95b1c2200b12"
     cluster="o3e9.099a95b1c2200b12"
     cluster_size="866 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="noobyprotect advml auto"
     md5_hashes="['32956417c653b302a2f4f66b7a6662e5', '2e3342ca6cfcc83eca35101b46637470', '0049368d6a12d38b98910cf3082e88c8']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(105472,1024) == "9458c8b09dab65de465bd0600b093996"
}

