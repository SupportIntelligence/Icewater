import "hash"

rule k3e9_0912f3a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0912f3a9c8000932"
     cluster="k3e9.0912f3a9c8000932"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor injector"
     md5_hashes="['d0a5fd1d779201cbe2211e6a3123acde', 'b018024fa5bfac57c7d55c267b7e778f', 'e9dfa40cc6d7fee366cce1dea3befa9d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

