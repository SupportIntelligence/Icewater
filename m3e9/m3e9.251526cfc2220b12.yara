import "hash"

rule m3e9_251526cfc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.251526cfc2220b12"
     cluster="m3e9.251526cfc2220b12"
     cluster_size="122 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus vbran jorik"
     md5_hashes="['c2b6198c058f8c7c21936b1423a07fb1', '5626dc4f3593e45f0c47c506e2e63bd3', 'c78715f4e0a3fceb9eb4be74f493ce71']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(119808,1024) == "99e71922aab9c4ec10fb2158329d29a0"
}

