import "hash"

rule n3f4_411c91adc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.411c91adc6220b12"
     cluster="n3f4.411c91adc6220b12"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="strictor cloudguard dnsunlocker"
     md5_hashes="['39dbf7eb0bca592f1906105e67ad0688', '61ea093f23de515a62026c82ac40ec63', '26d5daf92e9c534d4153c6fc196e17df']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(477696,1024) == "8f42cbeb8bf1647d5938061e83754512"
}

