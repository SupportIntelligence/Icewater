import "hash"

rule m3e9_1695b49495c94b66
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1695b49495c94b66"
     cluster="m3e9.1695b49495c94b66"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob sality"
     md5_hashes="['29895b573a6c7899477f7293e4d5da81', '29895b573a6c7899477f7293e4d5da81', '29895b573a6c7899477f7293e4d5da81']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(188416,1024) == "beda8ca5c5e5906392ea3aba919d45ab"
}

