import "hash"

rule n3e9_313c6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.313c6a48c0000b12"
     cluster="n3e9.313c6a48c0000b12"
     cluster_size="64 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="floxif pioneer fixflo"
     md5_hashes="['b4fa1afb9613efbb2fe4cce338d413f0', '3ec2d93e04d1356327741caa1c37d2ee', '3ef8395f9b5ed684882a60a1801938d3']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(250880,1195) == "cea0af9300573460ed7eed9fa45b702f"
}

