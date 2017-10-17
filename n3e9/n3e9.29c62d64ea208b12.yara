import "hash"

rule n3e9_29c62d64ea208b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c62d64ea208b12"
     cluster="n3e9.29c62d64ea208b12"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="crypt trojandropper cuegoe"
     md5_hashes="['13b9e383ff67e0643fe236afddc8b55f', '13b9e383ff67e0643fe236afddc8b55f', 'a041742a9937c5beb329fd1b9608d314']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(532460,1028) == "00fc4f62daf0da374568acfeb55d7e7f"
}

