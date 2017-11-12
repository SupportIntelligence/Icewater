import "hash"

rule m3e9_6136a0f969e21932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6136a0f969e21932"
     cluster="m3e9.6136a0f969e21932"
     cluster_size="540 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['d9a28781b4a7b9f220369581299bc38f', 'cc759259cdb42397e6b106f541800d50', '7c890b78689638a98e0c4f4d04ca8527']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(114176,1024) == "5e2651242e0cc956deeb0dfb4fe18279"
}

