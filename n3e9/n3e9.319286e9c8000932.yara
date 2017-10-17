import "hash"

rule n3e9_319286e9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.319286e9c8000932"
     cluster="n3e9.319286e9c8000932"
     cluster_size="43 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="cnum delf bafasy"
     md5_hashes="['4dc27dd85311d36205786a040deb7de1', 'cfa344c7b894744bbc61073c5c2c4abf', 'f1abfe423d70ec244b909af978056790']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(363904,1088) == "8786962f586598b5fd1054d1489b14e4"
}

