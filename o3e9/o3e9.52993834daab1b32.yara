import "hash"

rule o3e9_52993834daab1b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.52993834daab1b32"
     cluster="o3e9.52993834daab1b32"
     cluster_size="147 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy linkury bdff"
     md5_hashes="['f2e45ba2f14beb801e9c76245ee29e55', '2cbb5ffb96908cc6be906999626b359d', 'f67830e6669b23561e99897c12937b64']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(620544,1024) == "72beb9edbe73061adfcb3345c35a38b8"
}

