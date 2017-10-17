import "hash"

rule n3f0_296b8147cf82f133
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.296b8147cf82f133"
     cluster="n3f0.296b8147cf82f133"
     cluster_size="1533 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious heuristic attribute"
     md5_hashes="['0c7d4b92038ed5e7cb465c6f2d631a05', '29098675b61868ef74da54616b2cc21f', '0ee62b638697d6e681f933e16d6a6ff9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(681856,1152) == "364410b21d3a9ae28dd8dbd5bfc0aac4"
}

