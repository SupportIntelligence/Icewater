import "hash"

rule k3e9_391c16b8dd92f331
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c16b8dd92f331"
     cluster="k3e9.391c16b8dd92f331"
     cluster_size="183 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['01a52b2d865da50c2edd5e42126e5672', '80cca0dc8a8ddb2bf0ea0444c315869c', '63b643b7c42d8c4aa145c6184eea338b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(22016,1024) == "85735707a266c0c281df08fa16880c0c"
}

