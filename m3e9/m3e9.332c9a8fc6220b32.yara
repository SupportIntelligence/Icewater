import "hash"

rule m3e9_332c9a8fc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.332c9a8fc6220b32"
     cluster="m3e9.332c9a8fc6220b32"
     cluster_size="835 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus vbran autorun"
     md5_hashes="['7a2ddd1f3029f569423f104c6b8142e4', '3fcab5f9b14715df1b63f7fa509dd6bd', 'a68aae3794a716dc51a1feeae5a39d54']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(119808,1024) == "167709ba5441dbd5b814337c309ca8f4"
}

