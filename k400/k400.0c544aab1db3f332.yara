import "hash"

rule k400_0c544aab1db3f332
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k400.0c544aab1db3f332"
     cluster="k400.0c544aab1db3f332"
     cluster_size="3133 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kazy backdoor hupigon"
     md5_hashes="['2a1f79526effce8dcbc9c90148c5bc2f', '37a8646891972859275f054d3adee8fc', '31cb5a4fd5716e8b9925849bebce996a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(33792,1024) == "b5205cd8e88ce1fbfea05daac3792552"
}

