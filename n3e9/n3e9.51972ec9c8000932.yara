import "hash"

rule n3e9_51972ec9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.51972ec9c8000932"
     cluster="n3e9.51972ec9c8000932"
     cluster_size="9584 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="banker shiz backdoor"
     md5_hashes="['2adfefa90a9788147a4e448dc5dc3e19', '1994efe0d8c84109facf145066805a6b', '05fabb59a99b7fd6e0ad233244f2294b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(14120,1024) == "113b12abbc212dae31c2a6c7b4076c19"
}

