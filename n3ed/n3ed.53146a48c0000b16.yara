import "hash"

rule n3ed_53146a48c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.53146a48c0000b16"
     cluster="n3ed.53146a48c0000b16"
     cluster_size="76 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['e2cc15f15444c1d36df64c37cd8b60f3', '46abdf35e5b9d66d42f2419cd0d4606f', 'c383ff1d9595600e0161fd8883e4c993']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(138240,1536) == "c125b7c87b1684cc76c8a346e87e9126"
}

