import "hash"

rule n3f9_139a9299c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f9.139a9299c6200b12"
     cluster="n3f9.139a9299c6200b12"
     cluster_size="9185 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious ngrbot backdoor"
     md5_hashes="['0b13bc2779ca873c6bd9779ff1812a8c', '00a0648587a5eb3bc806404696d4c453', '0f676c66040d5691bc661c3cbb00cbb0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(17954,1026) == "2e637585e1260cd7c1a1182737db842b"
}

