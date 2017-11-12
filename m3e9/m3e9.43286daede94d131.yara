import "hash"

rule m3e9_43286daede94d131
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.43286daede94d131"
     cluster="m3e9.43286daede94d131"
     cluster_size="1956 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="coinminer zusy bitmin"
     md5_hashes="['5e6fad8efda952455ef7e029fd304106', '00fd1fd206f895ff1c125381a7be8805', '3419b64cd098a7dcaab98e0785a7be56']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(195614,1039) == "37c338ecb8e700cd6e0adde78b848030"
}

