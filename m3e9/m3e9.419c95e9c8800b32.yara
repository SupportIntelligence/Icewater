import "hash"

rule m3e9_419c95e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.419c95e9c8800b32"
     cluster="m3e9.419c95e9c8800b32"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack virut"
     md5_hashes="['b92af8a394ae483a929b7503904b5ddc', '54fdcf17734b7f0dfb4acf9073664f69', '4eaee440e1d2c14112ae85a562b690f3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(100864,1485) == "e2154669906715fd9e8b6ec07c4ee2f3"
}

