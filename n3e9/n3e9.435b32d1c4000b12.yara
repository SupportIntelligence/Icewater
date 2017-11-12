import "hash"

rule n3e9_435b32d1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.435b32d1c4000b12"
     cluster="n3e9.435b32d1c4000b12"
     cluster_size="1374 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['603e8d9560349af5f0b0054ab59c6b33', '0f7a82c1679e8c890a34985f7b664f55', '55875df4422b71830076d189df31184e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(242688,1110) == "587620e3cbd2bc91cd7bf6c50f251a7b"
}

