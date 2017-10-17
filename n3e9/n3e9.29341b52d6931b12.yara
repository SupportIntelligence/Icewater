import "hash"

rule n3e9_29341b52d6931b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29341b52d6931b12"
     cluster="n3e9.29341b52d6931b12"
     cluster_size="6624 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="parite pate pinfi"
     md5_hashes="['141fbe886ba6d38600888e1c69d1327e', '043d5a030f7581babe930dc2890995fb', '32bd28f9e754143d087b14571a8f7ce8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(617472,1024) == "1d22b8bf36c9e1d54c90541a81d93ba5"
}

