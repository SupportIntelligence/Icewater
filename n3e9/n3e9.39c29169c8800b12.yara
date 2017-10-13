import "hash"

rule n3e9_39c29169c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39c29169c8800b12"
     cluster="n3e9.39c29169c8800b12"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy trojandropper backdoor"
     md5_hashes="['9c56f2c2fe99866d4ed85a2351de0725', 'bea9ed758391674ec5eaf9749ec77138', 'bea9ed758391674ec5eaf9749ec77138']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(413696,1076) == "ab5c78a222b72df8502930b7c2966067"
}

