import "hash"

rule k403_139214f9c9000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k403.139214f9c9000b16"
     cluster="k403.139214f9c9000b16"
     cluster_size="23769 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="hackkms risktool riskware"
     md5_hashes="['00dd829124a4eb3a640e60639f6c2f4d', '0357a30306b768b99f64d923e8755271', '03ec6988514930145d55ece1a3756314']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "279ce4b1ac1ed45a1248ecc22de3d771"
}

