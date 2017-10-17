import "hash"

rule n3e9_1b1427a9c2000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b1427a9c2000b16"
     cluster="n3e9.1b1427a9c2000b16"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qvod jadtre viking"
     md5_hashes="['b2a70c127dd4c60190090722b942ddd1', 'a6c1abbc6cb8c7f9935f586e9a2ca0ca', 'b8688f3b9848c5f95f7b3dd56f6b09b3']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(57344,1024) == "17bb2f77974ec7dfe7028de9f705c059"
}

