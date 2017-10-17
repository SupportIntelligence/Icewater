import "hash"

rule n3f4_011494adc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.011494adc6220b12"
     cluster="n3f4.011494adc6220b12"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="strictor dnsunlocker cloudguard"
     md5_hashes="['8540dd7e5e5274cef2a22028e6daa912', '73bf04ec267fd4c385da9b8888bd6f8d', '24e328832881885388ed57d93d9e3d96']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(477696,1024) == "8f42cbeb8bf1647d5938061e83754512"
}

