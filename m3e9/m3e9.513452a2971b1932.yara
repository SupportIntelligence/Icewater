import "hash"

rule m3e9_513452a2971b1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.513452a2971b1932"
     cluster="m3e9.513452a2971b1932"
     cluster_size="75 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef jorik"
     md5_hashes="['a70204c987a1d120e1865156483d2374', 'c84f0f2895e5456e179e5c36b1a7fee4', '0ce943086c5d404c2723d1c6f9b9fb19']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(169984,1024) == "d84fc949386d6d90ce5be7cd4ca6e6b5"
}

