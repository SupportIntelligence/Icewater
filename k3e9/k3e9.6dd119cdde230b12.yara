import "hash"

rule k3e9_6dd119cdde230b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6dd119cdde230b12"
     cluster="k3e9.6dd119cdde230b12"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="attribute engine highconfidence"
     md5_hashes="['46607823edcadd80af749c72ff6dca00', '6dfb1903494ad2cbed8402774e653b50', '79d8a0397dbea66323b9877797837718']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1046) == "eceee49fef2454fdbdda19091afc21a3"
}

