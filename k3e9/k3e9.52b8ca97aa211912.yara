import "hash"

rule k3e9_52b8ca97aa211912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52b8ca97aa211912"
     cluster="k3e9.52b8ca97aa211912"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['38dbe37d2e3a11204febaf12bb85d474', '3923b1d5a3153b19319ff26701f5069f', '261f9db43db9dd948b5550952f55d49d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9560,1066) == "41225ea7cd7bc5ea699676982c5b42ce"
}

