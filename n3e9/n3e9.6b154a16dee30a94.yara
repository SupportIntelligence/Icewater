import "hash"

rule n3e9_6b154a16dee30a94
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6b154a16dee30a94"
     cluster="n3e9.6b154a16dee30a94"
     cluster_size="14146 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor shiz razy"
     md5_hashes="['02365098f9a8fcd3ef2aacf373fd2e75', '0928569ec3f42f11860b4b6eb0d8b500', '03ac9251f98dee70486dddb4d53bbc03']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(98304,1230) == "e5afe70561dbf1109a378cc52326c944"
}

