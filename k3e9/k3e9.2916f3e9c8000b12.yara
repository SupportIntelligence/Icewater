import "hash"

rule k3e9_2916f3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2916f3e9c8000b12"
     cluster="k3e9.2916f3e9c8000b12"
     cluster_size="443 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['6c11611c7d92a1f5fe948beaccec8495', '78b34578dbb41477817c8eeacc8a8081', '88c006e6c1825d08af0098f3aff23b8b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

