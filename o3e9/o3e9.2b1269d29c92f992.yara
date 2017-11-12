import "hash"

rule o3e9_2b1269d29c92f992
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2b1269d29c92f992"
     cluster="o3e9.2b1269d29c92f992"
     cluster_size="1719 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="dlboost installmonster installmonstr"
     md5_hashes="['1d66a2dbcb1f291510e93dca9e468d53', '1b35519e0ad670c4994645cb255fb45f', '08a48f89aaada1eb815ed7e8b4866421']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2511144,1060) == "aa0140156618c0f05045a17803676a99"
}

