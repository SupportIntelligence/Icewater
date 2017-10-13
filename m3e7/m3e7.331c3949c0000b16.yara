import "hash"

rule m3e7_331c3949c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.331c3949c0000b16"
     cluster="m3e7.331c3949c0000b16"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['acfdd2b09ee499f7f30d75b03a0614fc', 'acfdd2b09ee499f7f30d75b03a0614fc', 'a4ecdb27bc2611284932952933ca2126']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62090,1058) == "2cc91028f6f559f9c633c41bba0674cd"
}

