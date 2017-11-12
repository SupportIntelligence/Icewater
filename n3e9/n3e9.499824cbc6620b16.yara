import "hash"

rule n3e9_499824cbc6620b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.499824cbc6620b16"
     cluster="n3e9.499824cbc6620b16"
     cluster_size="31 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['c1c78147c8545445e3f17355ae972519', 'd3dd9a744ca7ee42c1282395d1ee9516', 'd607ffb05f23989297d480f72e167872']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(436736,1024) == "b7a5262ff43994734cf2fccdbf263cf3"
}

