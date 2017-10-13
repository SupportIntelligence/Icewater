import "hash"

rule m3e9_5256968b95a31b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5256968b95a31b12"
     cluster="m3e9.5256968b95a31b12"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbkrypt vobfus wbna"
     md5_hashes="['a6db54c1e62f5f4439b259c37a816b3b', 'a6db54c1e62f5f4439b259c37a816b3b', 'a6db54c1e62f5f4439b259c37a816b3b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(154624,1024) == "72d77f52733c530885ba251c08922e84"
}

