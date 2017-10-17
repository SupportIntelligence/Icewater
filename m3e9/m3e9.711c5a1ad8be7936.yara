import "hash"

rule m3e9_711c5a1ad8be7936
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.711c5a1ad8be7936"
     cluster="m3e9.711c5a1ad8be7936"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus vbinject wbna"
     md5_hashes="['d818882c19af92dfc80094d53abf0156', 'b2f7d35e9ddb83820bf2bf1ab4c6d15a', '1cd5e1a6980ec42bb991c61927088633']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(198656,1024) == "717cdae274e7ffe32ba8a1090986f9cc"
}

