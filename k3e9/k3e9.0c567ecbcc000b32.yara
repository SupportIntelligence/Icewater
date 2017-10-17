import "hash"

rule k3e9_0c567ecbcc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0c567ecbcc000b32"
     cluster="k3e9.0c567ecbcc000b32"
     cluster_size="169 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zbot upatre waski"
     md5_hashes="['d91345a5e26082d0c7ea77233e04d502', '1f8ef5fa827bb74622524df5ea961c4c', 'b6b6673b2db9da364c550e682c5de90f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16027,1075) == "962656d356117229635235f4e09e3d18"
}

