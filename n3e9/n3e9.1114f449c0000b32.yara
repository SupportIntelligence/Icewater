import "hash"

rule n3e9_1114f449c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1114f449c0000b32"
     cluster="n3e9.1114f449c0000b32"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="sirefef vobfus malicious"
     md5_hashes="['ab7f13d653ca92f46d5f1b1c9c353fc5', 'd2e14ad4798004a09ec6fb86d043ff87', 'bfaa1109b041d4ca54d432fa94c318dd']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(280576,1024) == "515f076c8bbdbe04e5c0fc90831af4fd"
}

