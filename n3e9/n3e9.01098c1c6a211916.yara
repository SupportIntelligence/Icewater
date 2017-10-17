import "hash"

rule n3e9_01098c1c6a211916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.01098c1c6a211916"
     cluster="n3e9.01098c1c6a211916"
     cluster_size="499 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="syncopate unwanted malicious"
     md5_hashes="['58fd643d9af4a96bd7d1f625f997bcd1', '9982a50a5b9d054c0e7ca99904a065f1', '58fd643d9af4a96bd7d1f625f997bcd1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(134144,1024) == "8facee2cdfd5014ae00f6960940fd8f0"
}

