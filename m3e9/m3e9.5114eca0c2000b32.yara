import "hash"

rule m3e9_5114eca0c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5114eca0c2000b32"
     cluster="m3e9.5114eca0c2000b32"
     cluster_size="4154 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="browsefox malicious riskware"
     md5_hashes="['0616b9c1d7bd56fd9850ffb9e3e771f8', '0d0091b99595c2112e3eaf2e67b8cebe', '2f4b3a26090be97fc44a48785ca6e3be']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(87552,1127) == "3d144ccf65f6637c7f40ecd7c1725647"
}

