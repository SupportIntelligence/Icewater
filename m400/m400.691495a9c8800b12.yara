import "hash"

rule m400_691495a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m400.691495a9c8800b12"
     cluster="m400.691495a9c8800b12"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="sality malicious sector"
     md5_hashes="['b9ecff083599b394b329b72f702f9ca4', '4be0c87f40ef39836cdbe8261ca5ab04', 'b9ecff083599b394b329b72f702f9ca4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(14336,1024) == "9e6cead361e0acd9a574017736bb5643"
}

