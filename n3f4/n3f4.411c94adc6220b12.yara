import "hash"

rule n3f4_411c94adc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.411c94adc6220b12"
     cluster="n3f4.411c94adc6220b12"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="strictor cloudguard dnsunlocker"
     md5_hashes="['11ccb14dfd44b6bca22b48980784942d', '86657ca9271b690581082995a4c604f8', '17239392097ce036ad399425bffa0c4c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(477696,1024) == "8f42cbeb8bf1647d5938061e83754512"
}

