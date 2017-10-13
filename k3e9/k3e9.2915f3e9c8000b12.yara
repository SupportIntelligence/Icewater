import "hash"

rule k3e9_2915f3e9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2915f3e9c8000b12"
     cluster="k3e9.2915f3e9c8000b12"
     cluster_size="75 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor razy simbot"
     md5_hashes="['a25851ea4f221df132ec78cabc2d4eb7', 'eb35aa3879b182a7adb8bb4b049c4c17', 'c9e0a7749826833a61186b9f8d7ee876']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

