import "hash"

rule k3e9_6d34f3429daae132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6d34f3429daae132"
     cluster="k3e9.6d34f3429daae132"
     cluster_size="13285 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre ipatre waski"
     md5_hashes="['0baa23fd97bb3715a5f3dd84af30b588', '0d42e40f3a4ff7f8455ccee58fb9536b', '0cbfe665edd2966c1d7c64447f92937c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8192,1024) == "2c6c7efefb34c2cc9ece6b483b5722e2"
}

