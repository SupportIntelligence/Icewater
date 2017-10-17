import "hash"

rule k3e9_3326b64bc6220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3326b64bc6220912"
     cluster="k3e9.3326b64bc6220912"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['8cfceb7229555e54507cb109e48a6d25', '49f6d01633f3edb7861071d1e5af9ac7', '49f6d01633f3edb7861071d1e5af9ac7']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "bafdc1c966710908612de8a0df7c0810"
}

