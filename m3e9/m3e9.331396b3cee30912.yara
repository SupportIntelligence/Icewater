import "hash"

rule m3e9_331396b3cee30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.331396b3cee30912"
     cluster="m3e9.331396b3cee30912"
     cluster_size="13728 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="mailru malicious riskware"
     md5_hashes="['053fed54710018888b28d63913026cbc', '0513669bb502d8d964a2d91401a479c1', '0511e9468fc2e47c7a7e333ede031aec']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(24714,1030) == "8d0ca0886a961b5ebddd0ce5f0e8edbd"
}

