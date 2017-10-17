import "hash"

rule o3e9_43b1dcb4ca010916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b1dcb4ca010916"
     cluster="o3e9.43b1dcb4ca010916"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob classic"
     md5_hashes="['0dce7bb915995d3af9ef4f17cf44d3c0', '8fab26f9d97f6e852c32a451399a3fa0', 'b38a67e7d29040350e72a9d116f81b49']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(561240,1025) == "99b65c777d372de5f7c792547b5e3c11"
}

