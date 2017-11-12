import "hash"

rule m3e9_43144888cb7b5132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.43144888cb7b5132"
     cluster="m3e9.43144888cb7b5132"
     cluster_size="22786 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor cripack vawtrak"
     md5_hashes="['014c8291b903a292dca08f84adecd915', '00d359d79f85ce83da6047d683d97860', '0328928f1969ac2a408919f816731ebf']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(200704,1024) == "5a2c5e94254309a31f721880a3fb930d"
}

