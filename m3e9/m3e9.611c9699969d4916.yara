import "hash"

rule m3e9_611c9699969d4916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c9699969d4916"
     cluster="m3e9.611c9699969d4916"
     cluster_size="493 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple virut rahack"
     md5_hashes="['afe5a07f9846860fb9888adfa41a405b', 'ac53e979c4e43c45f380c90b10531880', 'abf68176b61dec39ee3315f7e5bbceb9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(85504,1024) == "4f681858bf786cfccf1f8b6a25d36853"
}

