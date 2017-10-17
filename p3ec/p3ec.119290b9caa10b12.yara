import "hash"

rule p3ec_119290b9caa10b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3ec.119290b9caa10b12"
     cluster="p3ec.119290b9caa10b12"
     cluster_size="69 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="gorillaprice malicious high"
     md5_hashes="['0b4fb5c67da327edc624b3e6f4b731fe', '03073bcecbcab22cafaa897ff3cc4aaf', '85c12ee623db5e2cfb567d251c0c0991']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(231424,1024) == "8a924cdc0f112b75ad39cfef4894a4d0"
}

