import "hash"

rule m3e9_5256968b95a31b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5256968b95a31b12"
     cluster="m3e9.5256968b95a31b12"
     cluster_size="71 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbkrypt vobfus wbna"
     md5_hashes="['cb41dd20f40cff475cde7936296eee2d', 'ca86ac674a9a5894253e90d930042a3b', 'f2da66b8c0622393a12d31306e607233']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(154624,1024) == "72d77f52733c530885ba251c08922e84"
}

