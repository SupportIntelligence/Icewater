import "hash"

rule k403_1396b4f9c9000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k403.1396b4f9c9000b16"
     cluster="k403.1396b4f9c9000b16"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="hackkms risktool riskware"
     md5_hashes="['695a71aea0e2d2879dbe912df99777ac', '6aa257406f9f2162b139290d6deabec9', '1293b3f01430acc7539284916bd5820b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "1b02f02ac9669e5ee50ba580380dd5c3"
}

