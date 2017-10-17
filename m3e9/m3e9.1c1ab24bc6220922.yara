import "hash"

rule m3e9_1c1ab24bc6220922
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1c1ab24bc6220922"
     cluster="m3e9.1c1ab24bc6220922"
     cluster_size="31 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy androm backdoor"
     md5_hashes="['8e2fead12699a57037164bf8b65a8239', '01da75b68f80f3fb5ca079932d748b88', '5b66636eff6d9fc607011b7122ec2c2f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(20480,1024) == "13d3268c5c0285305299536cda4475aa"
}

