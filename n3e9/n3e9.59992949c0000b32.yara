import "hash"

rule n3e9_59992949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.59992949c0000b32"
     cluster="n3e9.59992949c0000b32"
     cluster_size="20 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbkrypt manbat eyestye"
     md5_hashes="['b97afe16d662efe2835251950df10113', 'a5d96abde8afc99200a03eba5b806c7b', 'b6b71ae42f64f19e8853c4d56f3af9db']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(294912,1024) == "0075faf39e2f7d6fb77b0d07d4aeffbe"
}

