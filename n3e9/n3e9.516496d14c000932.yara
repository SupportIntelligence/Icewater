import "hash"

rule n3e9_516496d14c000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.516496d14c000932"
     cluster="n3e9.516496d14c000932"
     cluster_size="130 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="mplug malicious firseria"
     md5_hashes="['486a0efd033fa1f0b3b8bad3851832de', '6cd07d8a27ec152f779de43c4f7db767', '7bd79e72f59e571236756810299e0fde']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(166096,1037) == "d839e6cce252173e8b908c6af28e47d8"
}

