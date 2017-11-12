import "hash"

rule m3e9_164b92c9c8000112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.164b92c9c8000112"
     cluster="m3e9.164b92c9c8000112"
     cluster_size="10425 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="tinba crypt emotet"
     md5_hashes="['03e80476415953c99cc14d40136796da', '0ada13bab708da750934c4257a62a4fb', '08f3959a21c23a3c1cf27bb3ba77030c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(6142,1024) == "e525bc9c21ab6fbf303b9c9addf3e980"
}

